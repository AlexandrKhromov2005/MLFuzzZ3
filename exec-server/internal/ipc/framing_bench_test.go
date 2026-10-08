package ipc

import (
	"bytes"
	"testing"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// BenchmarkWriteFrame measures the cost of marshalling an
// Envelope and emitting its framed bytes to an in-memory
// buffer. No network I/O.
func BenchmarkWriteFrame(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"in_0", 0},
		{"in_1K", 1024},
		{"in_64K", 64 * 1024},
	}
	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			env := &ipcv1.Envelope{
				Payload: &ipcv1.Envelope_RunRequest{
					RunRequest: &ipcv1.RunRequest{
						Input: make([]byte, sz.size),
					},
				},
			}
			b.SetBytes(int64(sz.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var buf bytes.Buffer
				if err := WriteFrame(&buf, env); err != nil {
					b.Fatalf("WriteFrame: %v", err)
				}
			}
		})
	}
}

// BenchmarkReadFrame measures the cost of parsing a framed
// envelope from an in-memory buffer, including the protobuf
// unmarshal step.
func BenchmarkReadFrame(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"in_0", 0},
		{"in_1K", 1024},
		{"in_64K", 64 * 1024},
	}
	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			env := &ipcv1.Envelope{
				Payload: &ipcv1.Envelope_RunRequest{
					RunRequest: &ipcv1.RunRequest{
						Input: make([]byte, sz.size),
					},
				},
			}
			var prelude bytes.Buffer
			if err := WriteFrame(&prelude, env); err != nil {
				b.Fatalf("prep: %v", err)
			}
			frameBytes := prelude.Bytes()

			b.SetBytes(int64(sz.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := bytes.NewReader(frameBytes)
				if _, err := ReadFrame(r); err != nil {
					b.Fatalf("ReadFrame: %v", err)
				}
			}
		})
	}
}
