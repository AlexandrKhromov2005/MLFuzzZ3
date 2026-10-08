package crashrec

// Duplicate-record harness: how many crash records are repeated
// submissions of an already recorded input, and what recording
// costs per execution.
//
// the driver lives inside internal/crashrec/ because a driver
// outside the mlfuzzz3/exec-server module fails to build with "use
// of internal package mlfuzzz3/exec-server/internal/crashrec not
// allowed". The ban on touching exec-server/ is lifted for this one
// new file only; crashrec.go and crashrec_test.go stay unchanged.
//
// Recording itself is not modified and no dedupe is switched on.
// Dedupe is MODELLED by counting input_sha256 over every meta.json
// the recorder wrote. The key is the sha256 of the INPUT, not a
// stack hash — records carry no stack.
//
// Two tests:
//   - TestDedupeHarnessControls runs in the gate: the record-off arm
//     writes nothing although the target crashed, the same crashing
//     input fed N times reads back as (N-1)/N duplicates, and N
//     distinct crashing inputs read back as zero duplicates.
//   - TestDedupeHarnessMeasurement runs only when
//     CRASHREC_DEDUPE_HARNESS_OUT names an output file (relative to
//     the repo root): N=10 repeats per arm over one stream of
//     mutations of a single seed, arms interleaved, raw per-run
//     lines plus medians written to that file. With
//     CRASHREC_DEDUPE_HARNESS_KEEP=1 the arm dirs stay on disk.
//
// Both arms go through the real cov_crash fixture via worker.Pool
// and call Record on every result, exactly like the handler in
// cmd/exec-server/main.go; they differ only in Config.Dir.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
	"mlfuzzz3/exec-server/internal/worker"
)

const (
	dedupeRepeats = 10

	// Stream: every input is dedupeSeed with 1..dedupeMaxFlips
	// random bit flips. The fixture aborts when bit 7 of the first
	// byte is set, so crashes come from flips of that bit.
	dedupeSeed         = "AAAA"
	dedupeMaxFlips     = 2
	dedupeRNGSeed      = 1
	dedupeDefaultInput = 2000
)

// dedupeCrashStatuses mirrors the -record-status default
// "crash,hang" of cmd/exec-server/main.go.
var dedupeCrashStatuses = []ipcv1.ExecStatus{
	ipcv1.ExecStatus_EXEC_STATUS_CRASH,
	ipcv1.ExecStatus_EXEC_STATUS_HANG,
}

// dedupeRepoRoot: this file is at exec-server/internal/crashrec/,
// ..×3 = repo root.
func dedupeRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(
		filepath.Dir(thisFile), "..", "..", ".."))
}

// ensureCovCrashTarget returns the path of the built cov_crash
// fixture, building it on demand. Skips when no build tree exists.
func ensureCovCrashTarget(t *testing.T, repoRoot string) string {
	t.Helper()
	buildDir := os.Getenv("BUILD_DIR")
	if buildDir == "" {
		buildDir = "build"
	}
	buildDir = filepath.Join(repoRoot, buildDir)
	targetPath := filepath.Join(buildDir,
		"tests", "fixtures", "cov_crash", "cov_crash_target")
	if _, err := os.Stat(targetPath); err == nil {
		return targetPath
	}
	if _, err := os.Stat(buildDir); err != nil {
		t.Skipf("build dir %q not found: %v", buildDir, err)
	}
	cmd := exec.Command("cmake", "--build", buildDir,
		"--target", "cov_crash_build")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("cmake build cov_crash_build failed: %v", err)
	}
	if _, err := os.Stat(targetPath); err != nil {
		t.Skipf("cov_crash_target missing after build: %v", err)
	}
	return targetPath
}

// dedupeStream builds n inputs, each a mutation of one seed, from a
// fixed RNG seed so every run of every arm sees the same stream.
func dedupeStream(n int) [][]byte {
	rng := rand.New(rand.NewSource(dedupeRNGSeed))
	out := make([][]byte, n)
	for i := range out {
		in := []byte(dedupeSeed)
		flips := 1 + rng.Intn(dedupeMaxFlips)
		for f := 0; f < flips; f++ {
			bit := rng.Intn(len(in) * 8)
			in[bit/8] ^= 1 << (bit % 8)
		}
		out[i] = in
	}
	return out
}

// dedupeRun is the timing side of one arm run.
type dedupeRun struct {
	execs      int
	crashes    int
	elapsed    time.Duration // Execute + Record over the stream
	recordTime time.Duration // Record calls only
}

// runDedupeArm feeds inputs through a fresh Pool and a Recorder
// whose Config differs between arms only in Dir ("" = record off).
func runDedupeArm(
	t *testing.T, target, dir string, inputs [][]byte,
) dedupeRun {
	t.Helper()
	pool, err := worker.NewPool(worker.Config{TargetPath: target})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	// Production logs every record at info; keep the formatting
	// cost but drop the bytes.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec, err := New(Config{
		Dir:      dir,
		Statuses: dedupeCrashStatuses,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("crashrec.New: %v", err)
	}

	ctx := context.Background()
	var run dedupeRun
	start := time.Now()
	for _, in := range inputs {
		result, err := pool.Execute(ctx, in)
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		run.execs++
		if result.Status == ipcv1.ExecStatus_EXEC_STATUS_CRASH {
			run.crashes++
		}
		recStart := time.Now()
		rec.Record(in, result)
		run.recordTime += time.Since(recStart)
	}
	run.elapsed = time.Since(start)
	return run
}

// dedupeScan is the on-disk side of one arm run.
type dedupeScan struct {
	dirsFound   int // <Dir>/<status>/<record> dirs found by walking
	metaParsed  int // meta.json files parsed, every one of them
	shaMismatch int // input.bin whose sha256 != meta input_sha256
	records     int
	distinct    int
	maxMult     int
	bytesOnDisk int64 // regular files under Dir
}

func (s dedupeScan) duplicateShare() float64 {
	if s.records == 0 {
		return 0
	}
	return float64(s.records-s.distinct) / float64(s.records)
}

// scanDedupe walks dir and models dedupe by input_sha256. A missing
// dir scans as empty.
func scanDedupe(t *testing.T, dir string) dedupeScan {
	t.Helper()
	var s dedupeScan
	mult := map[string]int{}
	err := filepath.WalkDir(dir, func(
		path string, d fs.DirEntry, err error,
	) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel != "." && len(strings.Split(rel, string(filepath.Separator))) == 2 {
				s.dirsFound++
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		s.bytesOnDisk += info.Size()
		if d.Name() != "meta.json" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var m metaJSON
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		s.metaParsed++
		mult[m.InputSHA256]++
		input, err := os.ReadFile(
			filepath.Join(filepath.Dir(path), "input.bin"))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(input)
		if hex.EncodeToString(sum[:]) != m.InputSHA256 {
			s.shaMismatch++
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("scan %s: %v", dir, err)
	}
	for _, n := range mult {
		s.records += n
		if n > s.maxMult {
			s.maxMult = n
		}
	}
	s.distinct = len(mult)
	return s
}

func TestDedupeHarnessControls(t *testing.T) {
	target := ensureCovCrashTarget(t, dedupeRepoRoot(t))
	root := t.TempDir()
	const n = dedupeRepeats

	same := make([][]byte, n)
	distinct := make([][]byte, n)
	for i := range same {
		same[i] = []byte{0xC1}
		distinct[i] = []byte{0x80 | byte(i)}
	}

	// control_off_zero: crashes happen, nothing reaches disk.
	offDir := filepath.Join(root, "rec_off")
	if err := os.MkdirAll(offDir, 0o755); err != nil {
		t.Fatal(err)
	}
	off := runDedupeArm(t, target, "", same)
	offScan := scanDedupe(t, offDir)
	if off.crashes != n {
		t.Fatalf("rec_off crashes = %d, want %d", off.crashes, n)
	}
	if offScan.records != 0 || offScan.bytesOnDisk != 0 ||
		offScan.dirsFound != 0 {
		t.Fatalf("rec_off wrote to disk: %+v", offScan)
	}

	// control_same_input: one crashing input N times.
	sameDir := filepath.Join(root, "rec_on_same")
	on := runDedupeArm(t, target, sameDir, same)
	sameScan := scanDedupe(t, sameDir)
	if on.crashes != n {
		t.Fatalf("rec_on crashes = %d, want %d", on.crashes, n)
	}
	want := float64(n-1) / float64(n)
	if sameScan.records != n || sameScan.distinct != 1 ||
		sameScan.maxMult != n ||
		sameScan.duplicateShare() != want {
		t.Fatalf("same input: %+v share=%.3f, want records=%d "+
			"distinct=1 share=%.3f",
			sameScan, sameScan.duplicateShare(), n, want)
	}

	// Distinct crashing inputs must not read as duplicates.
	distDir := filepath.Join(root, "rec_on_distinct")
	runDedupeArm(t, target, distDir, distinct)
	distScan := scanDedupe(t, distDir)
	if distScan.records != n || distScan.distinct != n ||
		distScan.duplicateShare() != 0 {
		t.Fatalf("distinct inputs: %+v", distScan)
	}

	for name, s := range map[string]dedupeScan{
		"same": sameScan, "distinct": distScan,
	} {
		if s.metaParsed != s.dirsFound || s.shaMismatch != 0 {
			t.Fatalf("%s: meta_parsed=%d dirs_found=%d "+
				"sha_mismatch=%d", name, s.metaParsed,
				s.dirsFound, s.shaMismatch)
		}
	}
}

// dedupeMedian is the true median (mean of the two middle values
// for even N), not sorted[n/2].
func dedupeMedian(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	m := len(s) / 2
	if len(s)%2 == 0 {
		return (s[m-1] + s[m]) / 2
	}
	return s[m]
}

func TestDedupeHarnessMeasurement(t *testing.T) {
	outRel := os.Getenv("CRASHREC_DEDUPE_HARNESS_OUT")
	if outRel == "" {
		t.Skip("CRASHREC_DEDUPE_HARNESS_OUT not set")
	}
	repoRoot := dedupeRepoRoot(t)
	target := ensureCovCrashTarget(t, repoRoot)
	inputs := dedupeDefaultInput
	if v := os.Getenv("CRASHREC_DEDUPE_HARNESS_INPUTS"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed <= 0 {
			t.Fatalf("CRASHREC_DEDUPE_HARNESS_INPUTS=%q", v)
		}
		inputs = parsed
	}
	scratch := os.Getenv("CRASHREC_DEDUPE_HARNESS_SCRATCH")
	if scratch == "" {
		scratch = t.TempDir()
	} else if !filepath.IsAbs(scratch) {
		scratch = filepath.Join(repoRoot, scratch)
	}
	// CRASHREC_DEDUPE_HARNESS_KEEP=1 leaves every arm dir on disk after
	// its scan, so the experiment can dump each meta.json as raw data.
	// Removal happens outside the timed region either way.
	keep := os.Getenv("CRASHREC_DEDUPE_HARNESS_KEEP") == "1"

	targetRel, err := filepath.Rel(repoRoot, target)
	if err != nil {
		t.Fatal(err)
	}
	stream := dedupeStream(inputs)

	var b strings.Builder
	fmt.Fprintf(&b, "# crashrec duplicate harness\n")
	fmt.Fprintf(&b, "# target=%s seed=%q max_flips=%d rng_seed=%d "+
		"inputs_per_repeat=%d repeats=%d "+
		"statuses=crash,hang logger=text_discard\n",
		targetRel, dedupeSeed, dedupeMaxFlips, dedupeRNGSeed,
		inputs, dedupeRepeats)

	perExec := map[string][]float64{}
	recPerExec := map[string][]float64{}
	execs := map[int]int{}
	var onScans []dedupeScan
	controlOffZero := true
	for r := 0; r < dedupeRepeats; r++ {
		order := []bool{true, false}
		if r%2 == 1 {
			order = []bool{false, true}
		}
		for pos, recOn := range order {
			name := "rec_off"
			if recOn {
				name = "rec_on"
			}
			armDir := filepath.Join(scratch,
				fmt.Sprintf("r%d_%s", r, name))
			if err := os.RemoveAll(armDir); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(armDir, 0o755); err != nil {
				t.Fatal(err)
			}
			cfgDir := ""
			if recOn {
				cfgDir = armDir
			}
			run := runDedupeArm(t, target, cfgDir, stream)
			scan := scanDedupe(t, armDir)
			if !keep {
				if err := os.RemoveAll(armDir); err != nil {
					t.Fatal(err)
				}
			}
			execs[run.execs]++
			us := float64(run.elapsed.Microseconds()) /
				float64(run.execs)
			recUs := float64(run.recordTime.Microseconds()) /
				float64(run.execs)
			perExec[name] = append(perExec[name], us)
			recPerExec[name] = append(recPerExec[name], recUs)
			if recOn {
				onScans = append(onScans, scan)
			} else if scan.records != 0 || scan.bytesOnDisk != 0 {
				controlOffZero = false
			}
			fmt.Fprintf(&b, "RUN arm=%s repeat=%d order=%d "+
				"execs=%d crashes=%d elapsed_us=%d "+
				"us_per_exec=%.1f record_us_total=%d "+
				"record_us_per_exec=%.1f records=%d "+
				"distinct=%d duplicate_share=%.3f "+
				"max_multiplicity=%d bytes_on_disk=%d "+
				"meta_parsed=%d dirs_found=%d "+
				"sha_mismatch=%d\n",
				name, r, pos, run.execs, run.crashes,
				run.elapsed.Microseconds(), us,
				run.recordTime.Microseconds(), recUs,
				scan.records, scan.distinct,
				scan.duplicateShare(), scan.maxMult,
				scan.bytesOnDisk, scan.metaParsed,
				scan.dirsFound, scan.shaMismatch)
		}
	}

	// control_same_input, recorded through the same harness path.
	sameDir := filepath.Join(scratch, "control_same_input")
	if err := os.RemoveAll(sameDir); err != nil {
		t.Fatal(err)
	}
	same := make([][]byte, dedupeRepeats)
	for i := range same {
		same[i] = []byte{0xC1}
	}
	runDedupeArm(t, target, sameDir, same)
	sameScan := scanDedupe(t, sameDir)
	if !keep {
		if err := os.RemoveAll(sameDir); err != nil {
			t.Fatal(err)
		}
	}

	onMed := dedupeMedian(perExec["rec_on"])
	offMed := dedupeMedian(perExec["rec_off"])
	controlOn := len(onScans) > 0
	for _, s := range onScans {
		if s.records == 0 || s.metaParsed != s.dirsFound {
			controlOn = false
		}
	}
	yesNo := map[bool]string{true: "yes", false: "no"}
	fmt.Fprintf(&b, "SUMMARY budget_equalized=%s "+
		"median_us_per_exec_rec_on=%.1f "+
		"median_us_per_exec_rec_off=%.1f rec_cost_us=%.1f "+
		"rec_share_of_exec=%.3f "+
		"median_record_us_per_exec_rec_on=%.1f "+
		"median_record_us_per_exec_rec_off=%.1f\n",
		yesNo[len(execs) == 1], onMed, offMed, onMed-offMed,
		(onMed-offMed)/onMed,
		dedupeMedian(recPerExec["rec_on"]),
		dedupeMedian(recPerExec["rec_off"]))
	fmt.Fprintf(&b, "CONTROL control_off_zero=%s "+
		"control_on_nonzero=%s control_same_input=%.3f "+
		"control_same_input_records=%d "+
		"control_same_input_expected=%.3f\n",
		yesNo[controlOffZero], yesNo[controlOn],
		sameScan.duplicateShare(), sameScan.records,
		float64(dedupeRepeats-1)/float64(dedupeRepeats))

	outPath := outRel
	if !filepath.IsAbs(outPath) {
		outPath = filepath.Join(repoRoot, outRel)
	}
	if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write %s: %v", outRel, err)
	}
	if !controlOffZero || !controlOn {
		t.Fatalf("instrument control failed: off_zero=%v "+
			"on_nonzero=%v", controlOffZero, controlOn)
	}
}
