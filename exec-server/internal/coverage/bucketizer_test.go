package coverage_test

import (
	"bytes"
	"encoding/hex"
	"math/bits"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"mlfuzzz3/exec-server/internal/coverage"
)

// expectedBucket reproduces the AFL-classic 8-bin scheme
// from ADR 0021 §Решение for use as a reference oracle.
func expectedBucket(v int) byte {
	switch {
	case v == 0:
		return 0x00
	case v == 1:
		return 0x01
	case v == 2:
		return 0x02
	case v == 3:
		return 0x04
	case v <= 7:
		return 0x08
	case v <= 15:
		return 0x10
	case v <= 31:
		return 0x20
	case v <= 127:
		return 0x40
	default:
		return 0x80
	}
}

// TestBucketLUTAllValues locks in the raw→bucket mapping
// across all 256 raw values against the ADR 0021 reference
// table. Any drift here is a soundness regression.
func TestBucketLUTAllValues(t *testing.T) {
	raw := make([]byte, coverage.MapSize)
	out := make([]byte, coverage.MapSize)
	for v := 0; v < 256; v++ {
		raw[v] = byte(v)
	}
	b := coverage.NewBucketizer()
	if err := b.Classify(raw, out); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	for v := 0; v < 256; v++ {
		got := out[v]
		want := expectedBucket(v)
		if got != want {
			t.Errorf("raw=%d: got 0x%02x, want 0x%02x",
				v, got, want)
		}
	}
}

// TestClassifyAliasingSafe verifies that Classify produces
// the correct bucketized output when raw and out are the
// same backing slice (in-place transform).
func TestClassifyAliasingSafe(t *testing.T) {
	buf := make([]byte, coverage.MapSize)
	for i := 0; i < 256; i++ {
		buf[i] = byte(i)
	}
	// Fill the rest with a known repeating pattern so we
	// can spot any out-of-bounds drift.
	for i := 256; i < coverage.MapSize; i++ {
		buf[i] = byte(i & 0xff)
	}

	b := coverage.NewBucketizer()
	if err := b.Classify(buf, buf); err != nil {
		t.Fatalf("Classify in-place: %v", err)
	}
	for v := 0; v < 256; v++ {
		want := expectedBucket(v)
		if buf[v] != want {
			t.Errorf("raw=%d: got 0x%02x, want 0x%02x",
				v, buf[v], want)
		}
	}
	// Spot-check the tail: each byte should equal the
	// bucket of its prior raw value.
	for i := 256; i < coverage.MapSize; i++ {
		want := expectedBucket(i & 0xff)
		if buf[i] != want {
			t.Fatalf("tail[%d]: got 0x%02x, want 0x%02x",
				i, buf[i], want)
		}
	}
}

// TestClassifySizeMismatch rejects non-MapSize inputs.
func TestClassifySizeMismatch(t *testing.T) {
	b := coverage.NewBucketizer()
	if err := b.Classify(
		make([]byte, 1), make([]byte, coverage.MapSize)); err == nil {
		t.Error("expected error for short raw")
	}
	if err := b.Classify(
		make([]byte, coverage.MapSize), make([]byte, 1)); err == nil {
		t.Error("expected error for short out")
	}
}

// TestUpdateSeenMonotonic verifies that re-applying the same
// bucketized bitmap produces popcount on the first call and
// zero on every subsequent call.
func TestUpdateSeenMonotonic(t *testing.T) {
	bucketized := make([]byte, coverage.MapSize)
	// Sparse, non-zero pattern: 0x07 at every 17th byte.
	want := uint32(0)
	for i := 0; i < coverage.MapSize; i += 17 {
		bucketized[i] = 0x07
		want += 3
	}

	b := coverage.NewBucketizer()
	got, err := b.UpdateSeen(bucketized)
	if err != nil {
		t.Fatalf("UpdateSeen 1: %v", err)
	}
	if got != want {
		t.Errorf("first call: got %d new edges, want %d",
			got, want)
	}

	for i := 0; i < 3; i++ {
		got, err = b.UpdateSeen(bucketized)
		if err != nil {
			t.Fatalf("UpdateSeen %d: %v", i+2, err)
		}
		if got != 0 {
			t.Errorf("repeat %d: got %d new edges, want 0",
				i+2, got)
		}
	}
}

// TestUpdateSeenAccumulates verifies that new bits in
// subsequent calls (bits not present in earlier calls) count
// exactly once.
func TestUpdateSeenAccumulates(t *testing.T) {
	first := make([]byte, coverage.MapSize)
	second := make([]byte, coverage.MapSize)
	// first contributes bit 0 at offset 0, bit 1 at offset 1.
	first[0] = 0x01
	first[1] = 0x02
	// second contributes bit 0 at offset 0 (already seen),
	// bit 1 at offset 2 (new), bit 7 at offset 1 (new).
	second[0] = 0x01
	second[1] = 0x82
	second[2] = 0x02

	b := coverage.NewBucketizer()
	got1, err := b.UpdateSeen(first)
	if err != nil {
		t.Fatalf("UpdateSeen 1: %v", err)
	}
	if got1 != 2 {
		t.Errorf("first call new = %d, want 2", got1)
	}
	got2, err := b.UpdateSeen(second)
	if err != nil {
		t.Fatalf("UpdateSeen 2: %v", err)
	}
	// second adds: bit 7 at offset 1 (new), bit 1 at offset 2 (new).
	if got2 != 2 {
		t.Errorf("second call new = %d, want 2", got2)
	}
}

// TestUpdateSeenSizeMismatch rejects non-MapSize inputs.
func TestUpdateSeenSizeMismatch(t *testing.T) {
	b := coverage.NewBucketizer()
	if _, err := b.UpdateSeen(make([]byte, 0)); err == nil {
		t.Error("expected error for empty buffer")
	}
	if _, err := b.UpdateSeen(
		make([]byte, coverage.MapSize-1)); err == nil {
		t.Error("expected error for short buffer")
	}
}

// TestUpdateSeenConcurrentExactlyOnce runs N goroutines that
// each call UpdateSeen with the same bucketized bitmap. Sum
// of the new-edge counts returned across all goroutines must
// equal popcount(bitmap): exactly one goroutine is credited
// with introducing each bit. Run under `go test -race` to
// catch any data race in seen-map mutation.
func TestUpdateSeenConcurrentExactlyOnce(t *testing.T) {
	bucketized := make([]byte, coverage.MapSize)
	want := uint32(0)
	// Dense pattern: 0xFF every 3 bytes.
	for i := 0; i < coverage.MapSize; i += 3 {
		bucketized[i] = 0xFF
		want += 8
	}
	// Cross-check.
	var checkPop uint32
	for _, v := range bucketized {
		checkPop += uint32(bits.OnesCount8(v))
	}
	if checkPop != want {
		t.Fatalf("test setup: popcount %d != want %d",
			checkPop, want)
	}

	const goroutines = 16
	b := coverage.NewBucketizer()
	results := make([]uint32, goroutines)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			n, err := b.UpdateSeen(bucketized)
			if err != nil {
				t.Errorf("goroutine %d: %v", idx, err)
				return
			}
			results[idx] = n
		}(g)
	}
	close(start)
	wg.Wait()

	var total uint32
	for _, r := range results {
		total += r
	}
	if total != want {
		t.Errorf("sum of new edges = %d, want %d "+
			"(exactly-once attribution violated)",
			total, want)
	}

	// Repeated call after concurrent burst must be zero.
	post, err := b.UpdateSeen(bucketized)
	if err != nil {
		t.Fatalf("post-burst UpdateSeen: %v", err)
	}
	if post != 0 {
		t.Errorf("post-burst new = %d, want 0", post)
	}
}

// TestSeenSnapshotCopy verifies SeenSnapshot returns a fresh
// 64 KiB buffer disconnected from the internal seen-map.
func TestSeenSnapshotCopy(t *testing.T) {
	bucketized := make([]byte, coverage.MapSize)
	bucketized[0] = 0xA5
	bucketized[1] = 0x5A

	b := coverage.NewBucketizer()
	if _, err := b.UpdateSeen(bucketized); err != nil {
		t.Fatalf("UpdateSeen: %v", err)
	}
	snap1 := b.SeenSnapshot()
	if len(snap1) != coverage.MapSize {
		t.Fatalf("snapshot len = %d, want %d",
			len(snap1), coverage.MapSize)
	}
	if snap1[0] != 0xA5 || snap1[1] != 0x5A {
		t.Errorf("snapshot[0..1] = %02x %02x, want a5 5a",
			snap1[0], snap1[1])
	}
	// Mutate snapshot; second snapshot must be unaffected.
	snap1[0] = 0
	snap2 := b.SeenSnapshot()
	if snap2[0] != 0xA5 {
		t.Errorf("snapshot not isolated: snap2[0] = %02x",
			snap2[0])
	}
}

// --- Counter-scheme switch (ADR 0021 Д5) ---------------------
//
// The two expectation vectors below are written out by hand and
// independently of the code under test: the log2 one is
// transcribed from ADR 0021 §Метрики успеха, the hit/miss one
// from the definition of the alternative scheme. Nothing here
// calls into bucketLUT, expectedBucket or the bucketizer to
// decide what the answer should be.

// schemeRange is one row of a raw→bucket table: every raw hit
// count in [lo, hi] maps to want.
type schemeRange struct {
	lo, hi int
	want   byte
}

// schemeLog2FromADR is the default table, transcribed from ADR
// 0021 §Метрики успеха, line for line:
//
//	{0→0x00, 1→0x01, 2→0x02, 3→0x04, 4..7→0x08, 8..15→0x10,
//	 16..31→0x20, 32..127→0x40, 128..255→0x80}
var schemeLog2FromADR = []schemeRange{
	{0, 0, 0x00},
	{1, 1, 0x01},
	{2, 2, 0x02},
	{3, 3, 0x04},
	{4, 7, 0x08},
	{8, 15, 0x10},
	{16, 31, 0x20},
	{32, 127, 0x40},
	{128, 255, 0x80},
}

// schemeHitMissVector is the alternative table: an edge was
// either taken or it was not, and how often is not recorded.
var schemeHitMissVector = []schemeRange{
	{0, 0, 0x00},
	{1, 255, 0x01},
}

// schemeExpand turns a range table into all 256 expected bytes,
// failing if the ranges do not tile 0..255 exactly once. The
// tiling check is what makes a hand-written table trustworthy:
// a typo in a boundary shows up as a gap or an overlap.
func schemeExpand(t *testing.T, rows []schemeRange) [256]byte {
	t.Helper()
	var out [256]byte
	var covered [256]bool
	for _, r := range rows {
		if r.lo < 0 || r.hi > 255 || r.lo > r.hi {
			t.Fatalf("bad range [%d,%d]", r.lo, r.hi)
		}
		for v := r.lo; v <= r.hi; v++ {
			if covered[v] {
				t.Fatalf("raw %d covered twice", v)
			}
			covered[v] = true
			out[v] = r.want
		}
	}
	for v := 0; v < 256; v++ {
		if !covered[v] {
			t.Fatalf("raw %d not covered by table", v)
		}
	}
	return out
}

// schemeClassifyAll runs every raw counter value 0..255 through
// Classify and returns the 256 resulting bytes.
func schemeClassifyAll() ([256]byte, error) {
	raw := make([]byte, coverage.MapSize)
	out := make([]byte, coverage.MapSize)
	for v := 0; v < 256; v++ {
		raw[v] = byte(v)
	}
	var got [256]byte
	if err := coverage.NewBucketizer().Classify(raw, out); err != nil {
		return got, err
	}
	copy(got[:], out[:256])
	return got, nil
}

// TestSchemeDefaultMatchesADR0021 pins the default: with
// BucketSchemeEnv unset, Classify must reproduce the ADR 0021
// table for all 256 counter values, byte for byte.
func TestSchemeDefaultMatchesADR0021(t *testing.T) {
	if got := coverage.ActiveScheme(); got != coverage.SchemeLog2 {
		t.Skipf("test process started with %s=%q, active scheme %q; "+
			"default can only be checked in a default process",
			coverage.BucketSchemeEnv,
			os.Getenv(coverage.BucketSchemeEnv), got)
	}
	want := schemeExpand(t, schemeLog2FromADR)
	got, err := schemeClassifyAll()
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got != want {
		t.Fatalf("default scheme differs from ADR 0021 table:\n got %s\nwant %s",
			hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
	}
}

// TestSchemeFromEnvMapping pins which environment values opt in.
// Everything unrecognised must fall back to the default.
func TestSchemeFromEnvMapping(t *testing.T) {
	cases := []struct {
		set  bool
		val  string
		want coverage.BucketScheme
	}{
		{false, "", coverage.SchemeLog2},
		{true, "", coverage.SchemeLog2},
		{true, "hitmiss", coverage.SchemeHitMiss},
		{true, "log2", coverage.SchemeLog2},
		{true, "HITMISS", coverage.SchemeLog2},
		{true, "hit-miss", coverage.SchemeLog2},
		{true, "1", coverage.SchemeLog2},
		{true, "nonsense", coverage.SchemeLog2},
	}
	for _, c := range cases {
		if c.set {
			t.Setenv(coverage.BucketSchemeEnv, c.val)
		} else {
			t.Setenv(coverage.BucketSchemeEnv, "x")
			if err := os.Unsetenv(coverage.BucketSchemeEnv); err != nil {
				t.Fatalf("Unsetenv: %v", err)
			}
		}
		if got := coverage.SchemeFromEnv(); got != c.want {
			t.Errorf("SchemeFromEnv with set=%v val=%q: got %q, want %q",
				c.set, c.val, got, c.want)
		}
	}
}

// schemeHelperEnv marks the re-executed test binary that prints
// its own classification table instead of running the suite.
const schemeHelperEnv = "MLFUZZZ3_SCHEME_HELPER"

// TestSchemeHelperProcess is not a test: it is the child half of
// TestSchemeInstalledFromEnvAtInit. It classifies all 256
// counter values in a freshly started process and prints the
// active scheme and the resulting bytes between markers.
func TestSchemeHelperProcess(t *testing.T) {
	if os.Getenv(schemeHelperEnv) != "1" {
		t.Skip("helper process only")
	}
	got, err := schemeClassifyAll()
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	t.Log("helper ran")
	if _, werr := os.Stdout.WriteString("SCHEME-BEGIN " +
		string(coverage.ActiveScheme()) + " " +
		hex.EncodeToString(got[:]) + " SCHEME-END\n"); werr != nil {
		t.Fatalf("write result: %v", werr)
	}
}

// schemeRunChild re-executes this test binary with the
// environment variable either set to val or removed, and returns
// the scheme the child reported together with its table.
func schemeRunChild(t *testing.T, set bool, val string) (string, [256]byte) {
	t.Helper()
	cmd := exec.Command(os.Args[0],
		"-test.run=^TestSchemeHelperProcess$", "-test.v")
	env := []string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, coverage.BucketSchemeEnv+"=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, schemeHelperEnv+"=1")
	if set {
		env = append(env, coverage.BucketSchemeEnv+"="+val)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child (set=%v val=%q) failed: %v\n%s",
			set, val, err, out)
	}
	var table [256]byte
	for _, line := range bytes.Split(out, []byte("\n")) {
		f := bytes.Fields(line)
		if len(f) != 4 || string(f[0]) != "SCHEME-BEGIN" ||
			string(f[3]) != "SCHEME-END" {
			continue
		}
		raw, derr := hex.DecodeString(string(f[2]))
		if derr != nil || len(raw) != 256 {
			t.Fatalf("child printed unparsable table: %v", derr)
		}
		copy(table[:], raw)
		return string(f[1]), table
	}
	t.Fatalf("child printed no marker line:\n%s", out)
	return "", table
}

// TestSchemeInstalledFromEnvAtInit is the end-to-end check of
// the switch: a real process start, the variable read by init,
// and the table Classify actually applies afterwards. Both modes
// are compared against their own hand-written vector, never
// against each other.
func TestSchemeInstalledFromEnvAtInit(t *testing.T) {
	wantLog2 := schemeExpand(t, schemeLog2FromADR)
	wantHitMiss := schemeExpand(t, schemeHitMissVector)

	// The two vectors must actually differ, otherwise the test
	// would pass no matter what the switch does. They agree only
	// on raw 0 (0x00) and raw 1 (0x01).
	diff := 0
	for v := 0; v < 256; v++ {
		if wantLog2[v] != wantHitMiss[v] {
			diff++
		}
	}
	if diff != 254 {
		t.Fatalf("vectors differ in %d of 256 values, want 254", diff)
	}

	gotScheme, gotTable := schemeRunChild(t, false, "")
	if gotScheme != string(coverage.SchemeLog2) {
		t.Errorf("unset: child reports scheme %q, want %q",
			gotScheme, coverage.SchemeLog2)
	}
	if gotTable != wantLog2 {
		t.Errorf("unset: table differs from ADR 0021 vector:\n got %s\nwant %s",
			hex.EncodeToString(gotTable[:]),
			hex.EncodeToString(wantLog2[:]))
	}

	gotScheme, gotTable = schemeRunChild(t, true, string(coverage.SchemeHitMiss))
	if gotScheme != string(coverage.SchemeHitMiss) {
		t.Errorf("hitmiss: child reports scheme %q, want %q",
			gotScheme, coverage.SchemeHitMiss)
	}
	if gotTable != wantHitMiss {
		t.Errorf("hitmiss: table differs from hit/miss vector:\n got %s\nwant %s",
			hex.EncodeToString(gotTable[:]),
			hex.EncodeToString(wantHitMiss[:]))
	}
}
