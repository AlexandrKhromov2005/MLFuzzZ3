package coverage

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"os"
	"sync"
)

// bucketLUT maps a raw hit count (0..255) to a single
// bit-set byte. Bit positions:
//
//	bit 0 — hit count 1
//	bit 1 — hit count 2
//	bit 2 — hit count 3
//	bit 3 — hit count 4..7
//	bit 4 — hit count 8..15
//	bit 5 — hit count 16..31
//	bit 6 — hit count 32..127
//	bit 7 — hit count 128..255
//
// Raw value 0 maps to 0x00 (edge not hit). AFL-classic 8-bin
// scheme; per ADR 0021 Task 8d.
var bucketLUT [256]byte

func init() {
	for v := 0; v < 256; v++ {
		switch {
		case v == 0:
			bucketLUT[v] = 0
		case v == 1:
			bucketLUT[v] = 1 << 0
		case v == 2:
			bucketLUT[v] = 1 << 1
		case v == 3:
			bucketLUT[v] = 1 << 2
		case v <= 7:
			bucketLUT[v] = 1 << 3
		case v <= 15:
			bucketLUT[v] = 1 << 4
		case v <= 31:
			bucketLUT[v] = 1 << 5
		case v <= 127:
			bucketLUT[v] = 1 << 6
		default:
			bucketLUT[v] = 1 << 7
		}
	}

	// Counter-scheme switch, ADR 0021 Д5. Keep the log2 table
	// just built, build the alternative next to it, then install
	// whichever scheme the environment names. With
	// BucketSchemeEnv unset this re-installs the very table built
	// above, so bucketLUT stays byte-for-byte what it was.
	log2LUT = bucketLUT
	for v := 1; v < 256; v++ {
		hitMissLUT[v] = 1 << 0
	}
	applyScheme(SchemeFromEnv())
}

// Bucketizer owns the global (process-lifetime) seen-map and
// implements the AFL-classic log2 bucketization of raw hit
// counts. One *Bucketizer per process; shared across workers.
// Per ADR 0021 Task 8d.
type Bucketizer struct {
	mu   sync.Mutex
	seen [MapSize]byte
}

// NewBucketizer constructs a Bucketizer with an empty
// (all-zero) seen-map. No external resources held; no Close
// required.
func NewBucketizer() *Bucketizer {
	return &Bucketizer{}
}

// Classify writes the bucketized form of raw[i] into out[i]
// for i in [0, MapSize). raw and out may alias (point at the
// same backing array); aliasing-safe because the transform is
// pointwise. Returns an error if either slice is not exactly
// MapSize bytes long. Pure transform — no shared state, safe
// to call concurrently from many goroutines.
func (b *Bucketizer) Classify(raw, out []byte) error {
	if len(raw) != MapSize {
		return errors.New(
			"coverage: Classify raw size mismatch")
	}
	if len(out) != MapSize {
		return errors.New(
			"coverage: Classify out size mismatch")
	}
	for i := 0; i < MapSize; i++ {
		out[i] = bucketLUT[raw[i]]
	}
	return nil
}

// UpdateSeen OR's bucketized into the global seen-map and
// returns the popcount of bits that were 0 in the seen-map
// before the OR (i.e., bits newly introduced by this Run).
// Returns an error if bucketized is not exactly MapSize bytes.
// Thread-safe under b.mu; concurrent callers serialize.
func (b *Bucketizer) UpdateSeen(bucketized []byte) (uint32, error) {
	if len(bucketized) != MapSize {
		return 0, errors.New(
			"coverage: UpdateSeen size mismatch")
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	// Process 8 bytes at a time. MapSize (64 KiB) is a
	// multiple of 8, so no trailing tail loop is required.
	// binary.LittleEndian compiles to a single 8-byte load
	// on amd64/arm64; bits.OnesCount64 to a POPCNT
	// instruction where available.
	var newBits uint32
	seen := b.seen[:]
	for i := 0; i < MapSize; i += 8 {
		bv := binary.LittleEndian.Uint64(bucketized[i:])
		sv := binary.LittleEndian.Uint64(seen[i:])
		nv := bv & ^sv
		if nv != 0 {
			newBits += uint32(bits.OnesCount64(nv))
			binary.LittleEndian.PutUint64(seen[i:], sv|nv)
		}
	}
	return newBits, nil
}

// SeenSnapshot returns a copy of the global seen-map (64
// KiB). Diagnostics / tests only; not on the hot path.
func (b *Bucketizer) SeenSnapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, MapSize)
	copy(out, b.seen[:])
	return out
}

// BucketScheme names a mapping from a raw hit count to the
// bit-set byte that coverage comparison works on. Added per ADR
// 0021 Д5 so the two mappings can be compared on a campaign
// without editing this file; the mapping itself is chosen once
// per process, never per Run.
type BucketScheme string

const (
	// SchemeLog2 is the AFL-classic 8-bin log2 mapping
	// documented on bucketLUT above. It is the default: an
	// unset, empty or unrecognised BucketSchemeEnv selects it.
	SchemeLog2 BucketScheme = "log2"

	// SchemeHitMiss folds every non-zero hit count onto bit 0.
	// Coverage then distinguishes only "edge taken" from "edge
	// not taken" and is blind to how often an edge was taken.
	SchemeHitMiss BucketScheme = "hitmiss"
)

// BucketSchemeEnv is the environment variable read once, at
// package init, to pick the scheme for the whole process.
const BucketSchemeEnv = "MLFUZZZ3_BUCKET_SCHEME"

// log2LUT holds the table init() builds, so that installing
// another scheme stays reversible; hitMissLUT holds the
// alternative. Both are filled at init, before any scheme is
// installed into bucketLUT.
var (
	log2LUT    [256]byte
	hitMissLUT [256]byte
)

// activeScheme records which table bucketLUT currently holds.
var activeScheme = SchemeLog2

// SchemeFromEnv maps the value of BucketSchemeEnv onto a scheme.
// Unset, empty and unrecognised values all yield SchemeLog2: the
// default changes only on an exact opt-in, never by accident.
func SchemeFromEnv() BucketScheme {
	switch os.Getenv(BucketSchemeEnv) {
	case string(SchemeHitMiss):
		return SchemeHitMiss
	default:
		return SchemeLog2
	}
}

// ActiveScheme reports the scheme Classify is currently
// applying. Diagnostics and tests.
func ActiveScheme() BucketScheme {
	return activeScheme
}

// applyScheme installs the table for s into bucketLUT. Called
// once from init with SchemeFromEnv(); tests call it directly to
// exercise both schemes and to restore the default afterwards.
// The scheme is process-wide configuration fixed before workers
// start, so this is not safe to call while Classify runs.
func applyScheme(s BucketScheme) {
	switch s {
	case SchemeHitMiss:
		bucketLUT = hitMissLUT
	default:
		s = SchemeLog2
		bucketLUT = log2LUT
	}
	activeScheme = s
}
