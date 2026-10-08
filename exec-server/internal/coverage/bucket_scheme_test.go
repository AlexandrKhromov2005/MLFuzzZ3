//go:build linux && amd64

package coverage_test

// Ground truth for the log2 bucketization scheme (ADR 0021) on REAL raw
// coverage maps (task-135).
//
// The scheme decides what counts as new coverage: the worker accepts an
// input into the corpus when Bucketizer.UpdateSeen reports new bits
// (pool.go). Until this file existed, no number said whether the eight-bin
// log2 table distinguishes a single input from a plain "hit or not hit"
// rule. The question is answerable without touching production code,
// because raw saturating counters are available on the Go side BEFORE
// bucketization: Channel.Read returns the raw map and the Bucketizer is a
// separate, explicit step.
//
// Method. One stream of raw maps is captured once from a real
// pass-instrumented fixture, encoded losslessly, and then replayed from
// its start through four independent classifiers:
//
//	P — production: coverage.Bucketizer (Classify + UpdateSeen);
//	R — replica:    the ADR-0021 table rebuilt here from its prose
//	                description, as an instrument control. P and R must
//	                agree on EVERY input; a disagreement means the rig is
//	                wrong and the numbers below mean nothing;
//	H — hit only:   one bit per cell, "was this edge ever hit";
//	W — raw:        no compression at all, a distinct (cell, raw value)
//	                pair is new coverage.
//
// By construction H is coarser than P and P is coarser than W, so the
// decision sets nest: H ⊆ P ⊆ W. The test asserts the nesting and reports
// the two gaps element-wise (per input), never by subtracting totals:
//
//	decided_by_bucket_only — inputs P accepts that H does not see at all;
//	lost_by_bucket         — inputs W accepts that P no longer sees.
//
// This file adds no production code and modifies none; bucketizer.go is
// untouched. It reuses oracleRepoRoot / oracleBuildDir /
// ensureCmakeTarget / ensureLibraryArtifact from pass_oracle_test.go.

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"mlfuzzz3/exec-server/internal/coverage"
)

const (
	// bucketInputs is the stream length. Thousands of inputs, not a
	// campaign — the queue entry budgets exactly this.
	bucketInputs = 2000

	// bucketMaxLen bounds the generated input length. The primary
	// fixture drains stdin in a 256-byte loop, so a length of L costs
	// L/256+1 iterations of the back edge; 65535 bytes therefore reach
	// iteration counts of 256 and exercise every one of the eight bins,
	// including the saturating top one.
	bucketMaxLen = 65535

	// bucketSeed seeds the xorshift64* generator below. An explicit
	// generator is used instead of math/rand so that the stream depends
	// on nothing but this constant.
	bucketSeed = 0x20260909
)

// bucketArm names one fixture the stream is captured from.
type bucketArm struct {
	name       string // short name printed into the artefact
	cmakeName  string // cmake --build --target ...
	fixtureDir string // tests/fixtures/<dir>
	binary     string // built binary name
	note       string
}

var bucketArms = []bucketArm{
	{
		name:       "cov_argv_target",
		cmakeName:  "cov_argv_build",
		fixtureDir: "cov_argv",
		binary:     "cov_argv_target",
		note:       "has a stdin-draining loop: hit counts vary with input length",
	},
	{
		name:       "cov_stdin_target",
		cmakeName:  "cov_stdin_build",
		fixtureDir: "cov_stdin",
		binary:     "cov_stdin_target",
		note:       "loop-free: every reached block is hit exactly once",
	},
}

// bucketRNG is xorshift64*, written out so the input stream is a pure
// function of bucketSeed and of nothing else.
type bucketRNG struct{ s uint64 }

func (r *bucketRNG) next() uint64 {
	r.s ^= r.s >> 12
	r.s ^= r.s << 25
	r.s ^= r.s >> 27
	return r.s * 2685821657736338717
}

// bucketReplicaLUT rebuilds the ADR-0021 table from its prose definition
// (bucketizer.go doc comment: bit 0 -> 1, bit 1 -> 2, bit 2 -> 3, bit 3 ->
// 4..7, bit 4 -> 8..15, bit 5 -> 16..31, bit 6 -> 32..127, bit 7 ->
// 128..255, and 0 -> 0x00). It is deliberately expressed as ranges rather
// than copied from the production switch, so that the control can fail.
func bucketReplicaLUT() [256]byte {
	var lut [256]byte
	ranges := []struct {
		lo, hi int
		bit    uint
	}{
		{1, 1, 0},
		{2, 2, 1},
		{3, 3, 2},
		{4, 7, 3},
		{8, 15, 4},
		{16, 31, 5},
		{32, 127, 6},
		{128, 255, 7},
	}
	for _, rg := range ranges {
		for v := rg.lo; v <= rg.hi; v++ {
			lut[v] = 1 << rg.bit
		}
	}
	return lut
}

// ---------- the stream: capture, encoding, decoding ----------

// bucketEncode appends one raw map to dst in the sparse form
//
//	uint32 nnz, then nnz * (uint16 cell index, uint8 raw value)
//
// all little-endian. Zero cells carry no information (the log2 table maps
// 0 to 0x00), so omitting them is lossless; bucketDecode reconstructs the
// full 64 KiB map and the capture loop verifies the reconstruction against
// the live map for every input.
func bucketEncode(dst []byte, raw []byte) []byte {
	var nnz uint32
	for _, v := range raw {
		if v != 0 {
			nnz++
		}
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], nnz)
	dst = append(dst, hdr[:]...)
	for i, v := range raw {
		if v == 0 {
			continue
		}
		var rec [3]byte
		binary.LittleEndian.PutUint16(rec[:2], uint16(i))
		rec[2] = v
		dst = append(dst, rec[:]...)
	}
	return dst
}

// bucketStream reads the encoded stream back from its very beginning.
type bucketStream struct {
	buf []byte
	off int
	m   []byte
}

func newBucketStream(buf []byte) *bucketStream {
	return &bucketStream{buf: buf, m: make([]byte, coverage.MapSize)}
}

// next decodes the following map into a reusable buffer, or reports
// exhaustion. The returned slice is valid until the next call.
func (s *bucketStream) next() ([]byte, bool) {
	if s.off >= len(s.buf) {
		return nil, false
	}
	for i := range s.m {
		s.m[i] = 0
	}
	nnz := int(binary.LittleEndian.Uint32(s.buf[s.off:]))
	s.off += 4
	for k := 0; k < nnz; k++ {
		idx := int(binary.LittleEndian.Uint16(s.buf[s.off:]))
		s.m[idx] = s.buf[s.off+2]
		s.off += 3
	}
	return s.m, true
}

// bucketSpawn runs binPath once with input delivered on stdin from a
// regular file. A regular file, not a pipe, is deliberate: read(2) then
// returns full 256-byte chunks, so the loop trip count of the primary
// fixture is a function of the input length alone and the capture is
// repeatable. A non-zero exit is normal here (one fixture aborts on some
// inputs) and is not an error; only a failure to spawn is.
func bucketSpawn(
	t *testing.T,
	ch *coverage.Channel,
	binPath, libPath, stdinPath string,
	input []byte,
) []byte {
	t.Helper()
	if err := os.WriteFile(stdinPath, input, 0o600); err != nil {
		t.Fatalf("write stdin file: %v", err)
	}
	f, err := os.Open(stdinPath)
	if err != nil {
		t.Fatalf("open stdin file: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := ch.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath)
	cmd.Stdin = f
	cmd.ExtraFiles = []*os.File{ch.MemfdFile()}
	cmd.Env = append(os.Environ(),
		"LD_PRELOAD="+libPath,
		"MLFUZZZ3_COV_FD=3",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Exit status is ignored on purpose: abort() is a legitimate
	// outcome for one of the fixtures and the map is already written.
	_ = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("target %s timed out: %v", binPath, ctx.Err())
	}
	bm, err := ch.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return bm
}

// ---------- the four classifiers ----------

// bucketProduction replays the stream through the production Bucketizer.
func bucketProduction(t *testing.T, buf []byte) ([]bool, int) {
	t.Helper()
	b := coverage.NewBucketizer()
	out := make([]byte, coverage.MapSize)
	s := newBucketStream(buf)
	var dec []bool
	for {
		raw, ok := s.next()
		if !ok {
			break
		}
		if err := b.Classify(raw, out); err != nil {
			t.Fatalf("Classify: %v", err)
		}
		n, err := b.UpdateSeen(out)
		if err != nil {
			t.Fatalf("UpdateSeen: %v", err)
		}
		dec = append(dec, n > 0)
	}
	var cells int
	for _, v := range b.SeenSnapshot() {
		cells += bits.OnesCount8(v)
	}
	return dec, cells
}

// bucketByLUT replays the stream through an arbitrary 256-entry table with
// its own seen-map. Used for both the replica log2 control and hit-only.
func bucketByLUT(buf []byte, lut [256]byte) ([]bool, int, [coverage.MapSize]byte) {
	var seen [coverage.MapSize]byte
	s := newBucketStream(buf)
	var dec []bool
	for {
		raw, ok := s.next()
		if !ok {
			break
		}
		newBits := 0
		for i := 0; i < coverage.MapSize; i++ {
			b := lut[raw[i]]
			nv := b &^ seen[i]
			if nv != 0 {
				newBits += bits.OnesCount8(nv)
				seen[i] |= nv
			}
		}
		dec = append(dec, newBits > 0)
	}
	var cells int
	for _, v := range seen {
		cells += bits.OnesCount8(v)
	}
	return dec, cells, seen
}

// bucketRawClassifier treats every distinct (cell, raw value) pair as its
// own coverage fact — no compression whatsoever. Value 0 means "edge not
// hit" and is not a fact, mirroring the log2 table's 0 -> 0x00.
func bucketRawClassifier(buf []byte) ([]bool, int) {
	seen := make([][4]uint64, coverage.MapSize)
	s := newBucketStream(buf)
	var dec []bool
	for {
		raw, ok := s.next()
		if !ok {
			break
		}
		newPairs := 0
		for i := 0; i < coverage.MapSize; i++ {
			v := raw[i]
			if v == 0 {
				continue
			}
			w, bit := v>>6, uint(v&63)
			if seen[i][w]&(1<<bit) == 0 {
				seen[i][w] |= 1 << bit
				newPairs++
			}
		}
		dec = append(dec, newPairs > 0)
	}
	var cells int
	for i := range seen {
		for w := 0; w < 4; w++ {
			cells += bits.OnesCount64(seen[i][w])
		}
	}
	return dec, cells
}

// bucketCountOnlyFirst counts positions where a is true and b is false.
// Element-wise over the per-input decisions; totals are never subtracted.
func bucketCountOnlyFirst(a, b []bool) int {
	n := 0
	for i := range a {
		if a[i] && !b[i] {
			n++
		}
	}
	return n
}

func bucketCountTrue(a []bool) int {
	n := 0
	for _, v := range a {
		if v {
			n++
		}
	}
	return n
}

// TestBucketizationSchemeOnRealMaps captures one stream of real raw
// coverage maps per fixture and replays it through the four classifiers.
// Every number it prints carries the BUCKET prefix and is consumed by
// docs/experiments/coverage-bucketization/collect.py.
func TestBucketizationSchemeOnRealMaps(t *testing.T) {
	if testing.Short() {
		t.Skip("coverage test skipped in short mode")
	}
	root := oracleRepoRoot(t)
	buildDir := oracleBuildDir(t, root)
	libPath := ensureLibraryArtifact(t, buildDir)

	// Paths are printed relative to the repository root: the artefact
	// must not carry anybody's home directory.
	relTo := func(p string) string {
		r, err := filepath.Rel(root, p)
		if err != nil {
			return filepath.Base(p)
		}
		return r
	}

	fmt.Printf("BUCKET meta map_size=%d\n", coverage.MapSize)
	fmt.Printf("BUCKET meta inputs_planned=%d\n", bucketInputs)
	fmt.Printf("BUCKET meta max_input_len=%d\n", bucketMaxLen)
	fmt.Printf("BUCKET meta seed=%#x\n", uint64(bucketSeed))
	fmt.Printf("BUCKET meta lib=%s\n", relTo(libPath))
	fmt.Printf("BUCKET meta arms=%d\n", len(bucketArms))

	replica := bucketReplicaLUT()
	var hitOnly [256]byte
	for v := 1; v < 256; v++ {
		hitOnly[v] = 1
	}

	stdinPath := filepath.Join(t.TempDir(), "input.bin")

	for _, arm := range bucketArms {
		binPath := ensureCmakeTarget(t, buildDir, arm.cmakeName,
			filepath.Join(buildDir, "tests", "fixtures",
				arm.fixtureDir, arm.binary))

		ch, err := coverage.NewChannel(libPath)
		if err != nil {
			t.Fatalf("NewChannel: %v", err)
		}

		// ---- capture the stream exactly once ----
		rng := bucketRNG{s: bucketSeed}
		stream := make([]byte, 0, 1<<20)
		check := make([]byte, coverage.MapSize)
		lossy, empty, maxRaw := 0, 0, 0
		lenHist := map[int]int{}
		for i := 0; i < bucketInputs; i++ {
			n := int(rng.next() % (bucketMaxLen + 1))
			in := make([]byte, n)
			for j := range in {
				in[j] = byte(rng.next())
			}
			lenHist[n/256]++
			raw := bucketSpawn(t, ch, binPath, libPath, stdinPath, in)
			nz := 0
			for _, v := range raw {
				if v != 0 {
					nz++
				}
				if int(v) > maxRaw {
					maxRaw = int(v)
				}
			}
			if nz == 0 {
				empty++
			}
			before := len(stream)
			stream = bucketEncode(stream, raw)
			// Lossless check: decode what was just appended and
			// compare it against the live map, cell by cell.
			s := newBucketStream(stream[before:])
			back, ok := s.next()
			if !ok {
				t.Fatalf("re-decode failed at input %d", i)
			}
			copy(check, back)
			if !bytes.Equal(check, raw) {
				lossy++
			}
		}
		if cerr := ch.Close(); cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
		if lossy != 0 {
			t.Fatalf("%s: sparse encoding lost %d of %d maps",
				arm.name, lossy, bucketInputs)
		}

		sum := md5.Sum(stream)

		// ---- replay: each classifier reads the stream from its start ----
		decP, cellsP := bucketProduction(t, stream)
		decR, cellsR, seenR := bucketByLUT(stream, replica)
		decH, cellsH, _ := bucketByLUT(stream, hitOnly)
		decW, cellsW := bucketRawClassifier(stream)

		mismatch := 0
		for i := range decP {
			if decP[i] != decR[i] {
				mismatch++
			}
		}

		p := func(k string, v interface{}) {
			fmt.Printf("BUCKET %s %s=%v\n", arm.name, k, v)
		}
		p("target_path", relTo(binPath))
		p("note", arm.note)
		p("inputs_total", len(decP))
		p("maps_captured", len(decP))
		p("stream_bytes", len(stream))
		p("stream_md5", fmt.Sprintf("%x", sum))
		p("stream_lossless_mismatches", lossy)
		p("empty_maps", empty)
		p("max_raw_counter", maxRaw)
		p("accepted_log2", bucketCountTrue(decP))
		p("accepted_log2_replica", bucketCountTrue(decR))
		p("accepted_hitonly", bucketCountTrue(decH))
		p("accepted_raw", bucketCountTrue(decW))
		p("cells_log2", cellsP)
		p("cells_log2_replica", cellsR)
		p("cells_hitonly", cellsH)
		p("cells_raw", cellsW)
		p("control_decision_mismatches", mismatch)
		p("decided_by_bucket_only", bucketCountOnlyFirst(decP, decH))
		p("lost_by_bucket", bucketCountOnlyFirst(decW, decP))
		p("hitonly_not_log2", bucketCountOnlyFirst(decH, decP))
		p("log2_not_raw", bucketCountOnlyFirst(decP, decW))
		for b := 0; b < 8; b++ {
			cnt := 0
			for _, v := range seenR {
				if v&(1<<uint(b)) != 0 {
					cnt++
				}
			}
			p(fmt.Sprintf("bucketbit_%d_cells", b), cnt)
		}
		keys := make([]int, 0, len(lenHist))
		for k := range lenHist {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		p("len_buckets_256b", len(keys))

		// The instrument control is an assertion, not just a number:
		// a replica that disagrees with production invalidates the rig.
		if mismatch != 0 {
			t.Fatalf("%s: control failed, replica and production "+
				"disagreed on %d of %d inputs",
				arm.name, mismatch, len(decP))
		}
		if bucketCountTrue(decP) != bucketCountTrue(decR) {
			t.Fatalf("%s: control failed, accepted %d vs %d",
				arm.name, bucketCountTrue(decP), bucketCountTrue(decR))
		}
		if cellsP != cellsR {
			t.Fatalf("%s: control failed, cells %d vs %d",
				arm.name, cellsP, cellsR)
		}
		// The nesting H ⊆ P ⊆ W is a property of the tables, so a
		// violation would also mean the rig is wrong.
		if n := bucketCountOnlyFirst(decH, decP); n != 0 {
			t.Fatalf("%s: hit-only accepted %d inputs log2 did not", arm.name, n)
		}
		if n := bucketCountOnlyFirst(decP, decW); n != 0 {
			t.Fatalf("%s: log2 accepted %d inputs the raw counter did not", arm.name, n)
		}
	}
}
