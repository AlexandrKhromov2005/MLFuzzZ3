package coverage_test

import (
	"testing"

	"mlfuzzz3/exec-server/internal/coverage"
)

// BenchmarkClassify measures the raw→bucket transform over
// the full 64 KiB bitmap with aliasing input (in-place).
// ADR 0021 §Метрики успеха sets the budget at < 50 µs / 64 KiB
// on commodity x86_64.
func BenchmarkClassify(b *testing.B) {
	buf := make([]byte, coverage.MapSize)
	for i := range buf {
		buf[i] = byte(i & 0xff)
	}
	bk := coverage.NewBucketizer()

	b.SetBytes(int64(coverage.MapSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := bk.Classify(buf, buf); err != nil {
			b.Fatalf("Classify: %v", err)
		}
	}
}

// BenchmarkUpdateSeen measures the seen-map OR + popcount
// over the full 64 KiB bitmap. ADR 0021 §Метрики успеха sets
// the budget at < 20 µs / 64 KiB on commodity x86_64.
//
// The seen-map saturates after the first call, so subsequent
// iterations measure the steady-state OR cost (the popcount
// of newly-introduced bits is zero, matching the hot path
// once a fuzzing campaign reaches a stable coverage plateau).
func BenchmarkUpdateSeen(b *testing.B) {
	bucketized := make([]byte, coverage.MapSize)
	for i := range bucketized {
		bucketized[i] = byte(i & 0xff)
	}
	bk := coverage.NewBucketizer()

	b.SetBytes(int64(coverage.MapSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bk.UpdateSeen(bucketized); err != nil {
			b.Fatalf("UpdateSeen: %v", err)
		}
	}
}
