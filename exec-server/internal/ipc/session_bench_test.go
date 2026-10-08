package ipc

import (
	"context"
	"net"
	"testing"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// BenchmarkIPCRoundTrip measures one Run roundtrip through
// the full session layer: client WriteEnvelope(RunRequest) →
// server ReadEnvelope → handler → WriteEnvelope(RunResponse)
// → client ReadEnvelope.
//
// No fork, no filesystem. Pure framing + protobuf marshal +
// in-memory pipe roundtrip. This is the floor for per-run
// IPC overhead.
func BenchmarkIPCRoundTrip(b *testing.B) {
	inputSizes := []struct {
		name string
		size int
	}{
		{"in_0", 0},
		{"in_1K", 1024},
		{"in_64K", 64 * 1024},
	}

	for _, sz := range inputSizes {
		b.Run(sz.name, func(b *testing.B) {
			benchmarkIPCRoundTrip(b, sz.size)
		})
	}
}

func benchmarkIPCRoundTrip(b *testing.B, inputSize int) {
	clientSide, serverSide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = serverSide.Close() }()

	clientConn := NewConn(clientSide)
	serverConn := NewConn(serverSide)

	handler := func(
		_ context.Context,
		_ *ipcv1.RunRequest,
	) (*ipcv1.RunResponse, error) {
		return &ipcv1.RunResponse{
			Status: ipcv1.ExecStatus_EXEC_STATUS_OK,
		}, nil
	}

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- Serve(
			context.Background(),
			serverConn,
			ServerConfig{},
			handler)
	}()

	sess, err := Dial(
		context.Background(),
		clientConn,
		ClientConfig{
			RunTimeoutMs:     1000,
			ExpectedChannels: 0,
		})
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}

	input := make([]byte, inputSize)
	ctx := context.Background()

	b.SetBytes(int64(inputSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sess.Run(ctx, input); err != nil {
			b.Fatalf("Run: %v", err)
		}
	}
	b.StopTimer()

	_ = sess.Shutdown(ctx)
	<-serverDone
}
