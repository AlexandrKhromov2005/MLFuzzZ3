//go:build linux

package coverage_test

import (
	"math/rand/v2"
	"os"
	"testing"

	"mlfuzzz3/exec-server/internal/coverage"
)

// Map-read path of worker.Pool.Run (exec-server/internal/worker/pool.go):
// ch.Reset() before spawn, then after the target exits ch.Read() (fresh
// 64 KiB copy) and one pass over the copy counting non-zero bytes. The
// benchmarks below time each step on its own, the three steps together,
// and a control that does the same kind of work without touching the map.

// denseSlots is the number of occupied map slots on the dense generated
// target: docs/experiments/instrumentation-numbering-dense-map/report.md
// VERDICT slots_occupied=17649 (every probe of that target fired).
const denseSlots = 17649

var (
	sinkMap  []byte
	sinkHits int
)

func newBenchChannel(b *testing.B) *coverage.Channel {
	b.Helper()
	f, err := os.CreateTemp(b.TempDir(), "fake-cov-*.so")
	if err != nil {
		b.Fatalf("CreateTemp: %v", err)
	}
	if err := f.Close(); err != nil {
		b.Fatalf("close: %v", err)
	}
	ch, err := coverage.NewChannel(f.Name())
	if err != nil {
		b.Fatalf("NewChannel: %v", err)
	}
	b.Cleanup(func() { _ = ch.Close() })
	return ch
}

// denseImage returns a MapSize image with exactly denseSlots non-zero
// bytes at pseudo-random positions (fixed seed): edge ids are hashed, so
// hits do not cluster and the non-zero test does not predict well.
func denseImage() []byte {
	img := make([]byte, coverage.MapSize)
	r := rand.New(rand.NewPCG(20260915, 174))
	for _, i := range r.Perm(coverage.MapSize)[:denseSlots] {
		img[i] = byte(1 + r.IntN(255))
	}
	return img
}

// fillMap plays the target: writes img into the shared memfd, which the
// channel sees through its MAP_SHARED mapping.
func fillMap(b *testing.B, ch *coverage.Channel, img []byte) {
	if _, err := ch.MemfdFile().WriteAt(img, 0); err != nil {
		b.Fatalf("WriteAt: %v", err)
	}
}

// countHits is the loop of pool.go verbatim.
func countHits(bm []byte) int {
	hits := 0
	for _, b := range bm {
		if b != 0 {
			hits++
		}
	}
	return hits
}

func BenchmarkMapReadPath(b *testing.B) {
	fills := []struct {
		name string
		img  []byte // nil: target wrote nothing
		hits int
	}{
		{"empty", nil, 0},
		{"dense", denseImage(), denseSlots},
	}

	for _, fl := range fills {
		b.Run("reset/"+fl.name, func(b *testing.B) {
			ch := newBenchChannel(b)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if fl.img != nil {
					b.StopTimer()
					fillMap(b, ch, fl.img)
					b.StartTimer()
				}
				if err := ch.Reset(); err != nil {
					b.Fatalf("Reset: %v", err)
				}
			}
		})

		b.Run("read/"+fl.name, func(b *testing.B) {
			ch := newBenchChannel(b)
			if fl.img != nil {
				fillMap(b, ch, fl.img)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				bm, err := ch.Read()
				if err != nil {
					b.Fatalf("Read: %v", err)
				}
				sinkMap = bm
			}
			b.StopTimer()
			if got := countHits(sinkMap); got != fl.hits {
				b.Fatalf("read copy has %d non-zero bytes, want %d", got, fl.hits)
			}
		})

		b.Run("hitcount/"+fl.name, func(b *testing.B) {
			ch := newBenchChannel(b)
			if fl.img != nil {
				fillMap(b, ch, fl.img)
			}
			bm, err := ch.Read()
			if err != nil {
				b.Fatalf("Read: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hits := 0
				for _, v := range bm {
					if v != 0 {
						hits++
					}
				}
				sinkHits = hits
			}
			b.StopTimer()
			if sinkHits != fl.hits {
				b.Fatalf("hits = %d, want %d", sinkHits, fl.hits)
			}
		})

		// whole: the sequence of one Run. The fill between Reset and
		// Read is the target's work, not the server's, so it is untimed.
		b.Run("whole/"+fl.name, func(b *testing.B) {
			ch := newBenchChannel(b)
			if fl.img != nil {
				fillMap(b, ch, fl.img)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := ch.Reset(); err != nil {
					b.Fatalf("Reset: %v", err)
				}
				if fl.img != nil {
					b.StopTimer()
					fillMap(b, ch, fl.img)
					b.StartTimer()
				}
				bm, err := ch.Read()
				if err != nil {
					b.Fatalf("Read: %v", err)
				}
				sinkHits = countHits(bm)
			}
			b.StopTimer()
			if sinkHits != fl.hits {
				b.Fatalf("hits = %d, want %d", sinkHits, fl.hits)
			}
		})
	}

	// resetbranch: the other zeroing on the same pre-spawn path
	// (ch.ResetBranch, BranchSegmentSize bytes). Not part of reading the
	// edge map; timed so the border balance can name it separately.
	b.Run("resetbranch/empty", func(b *testing.B) {
		ch := newBenchChannel(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ch.ResetBranch(); err != nil {
				b.Fatalf("ResetBranch: %v", err)
			}
		}
	})

	// Instrument controls: the same allocate/copy/count shape over one
	// byte that is not the map, and an empty loop body. Both must come out
	// orders of magnitude below read/ and whole/, otherwise the numbers
	// above measure the harness, not the map.
	b.Run("control/copy1", func(b *testing.B) {
		src := []byte{1}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out := make([]byte, len(src))
			copy(out, src)
			sinkHits = countHits(out)
		}
	})

	b.Run("control/noop", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sinkHits = i
		}
	})
}
