package ipc

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// echoHandler returns a RunResponse with RunId set by caller
// and status OK, echoing nothing meaningful — suitable for
// testing lifecycle, not payload semantics.
func echoHandler(
	ctx context.Context,
	req *ipcv1.RunRequest,
) (*ipcv1.RunResponse, error) {
	_ = ctx
	_ = req
	return &ipcv1.RunResponse{
		Status: ipcv1.ExecStatus_EXEC_STATUS_OK,
	}, nil
}

// TestSessionHappyPath: full lifecycle with 1 channel,
// 3 runs, clean shutdown.
func TestSessionHappyPath(t *testing.T) {
	clientConn, serverConn := pipeConns()
	defer func() { _ = clientConn.Close() }()

	ch := &ipcv1.ChannelAnnouncement{
		Descriptor_: &ipcv1.ChannelAnnouncement_Edge{
			Edge: &ipcv1.EdgeCoverageDescriptor{
				ShmName:       "edge-test",
				Offset:        0,
				Length:        65536,
				SchemaVersion: 1,
			},
		},
	}

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- Serve(
			context.Background(),
			serverConn,
			ServerConfig{
				Channels: []ChannelWithFD{
					{Announcement: ch, FD: -1},
				},
			},
			echoHandler)
	}()

	sess, err := Dial(
		context.Background(),
		clientConn,
		ClientConfig{
			RunTimeoutMs:     500,
			ExpectedChannels: 1,
		})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	for i := 0; i < 3; i++ {
		resp, err := sess.Run(
			context.Background(),
			[]byte("run"))
		if err != nil {
			t.Fatalf("Run %d: %v", i, err)
		}
		if resp.Status !=
			ipcv1.ExecStatus_EXEC_STATUS_OK {
			t.Errorf("Run %d: status %v", i, resp.Status)
		}
		if resp.RunId != uint64(i+1) {
			t.Errorf("Run %d: run_id = %d, want %d",
				i, resp.RunId, i+1)
		}
	}

	if err := sess.Shutdown(
		context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Errorf("Serve returned: %v", err)
	}
}

// TestSessionVersionMismatch: client with major=1 dials a
// server that replies major=2. Both should surface
// ErrVersionMismatch.
//
// We simulate the server by hand-rolling InitResponse instead
// of using Serve (which always replies with its own major).
func TestSessionVersionMismatch(t *testing.T) {
	clientConn, serverConn := pipeConns()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	go func() {
		// Read the InitRequest, ignore it, send a mismatched
		// InitResponse.
		_, _ = serverConn.ReadEnvelope()
		_ = serverConn.WriteEnvelope(&ipcv1.Envelope{
			Payload: &ipcv1.Envelope_InitResponse{
				InitResponse: &ipcv1.InitResponse{
					ProtocolVersionMajor: 2,
					ProtocolVersionMinor: 0,
				},
			},
		})
	}()

	_, err := Dial(
		context.Background(),
		clientConn,
		ClientConfig{ExpectedChannels: 0})
	if !errors.Is(err, ErrVersionMismatch) {
		t.Errorf("expected ErrVersionMismatch, got %v", err)
	}
}

// TestSessionUnexpectedEnvelope: server sends ShutdownResponse
// when client expects InitResponse.
func TestSessionUnexpectedEnvelope(t *testing.T) {
	clientConn, serverConn := pipeConns()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	go func() {
		_, _ = serverConn.ReadEnvelope()
		_ = serverConn.WriteEnvelope(&ipcv1.Envelope{
			Payload: &ipcv1.Envelope_ShutdownResponse{
				ShutdownResponse: &ipcv1.ShutdownResponse{},
			},
		})
	}()

	_, err := Dial(
		context.Background(),
		clientConn,
		ClientConfig{ExpectedChannels: 0})
	if !errors.Is(err, ErrUnexpectedEnvelope) {
		t.Errorf("expected ErrUnexpectedEnvelope, got %v", err)
	}
}

// TestSessionAbruptDisconnect: client closes mid-session;
// Serve should return a wrapped error (likely EOF or
// io.ErrClosedPipe).
func TestSessionAbruptDisconnect(t *testing.T) {
	clientConn, serverConn := pipeConns()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- Serve(
			context.Background(),
			serverConn,
			ServerConfig{},
			echoHandler)
	}()

	_, err := Dial(
		context.Background(),
		clientConn,
		ClientConfig{ExpectedChannels: 0})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := clientConn.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	serverErr := <-serverErrCh
	if serverErr == nil {
		t.Error(
			"expected non-nil error from Serve on abrupt " +
				"client disconnect")
	}
	// We don't assert a specific error kind; any wrapped
	// transport failure is acceptable. Verify at least that
	// it is not ErrUnexpectedEnvelope (that would be a
	// bug in our state machine, not a transport issue).
	if errors.Is(serverErr, ErrUnexpectedEnvelope) {
		t.Errorf(
			"abrupt disconnect should not surface as "+
				"ErrUnexpectedEnvelope, got %v", serverErr)
	}
	_ = io.EOF // reference for import discipline
}

// pipeConns is a helper that wraps net.Pipe into two Conns.
func pipeConns() (*Conn, *Conn) {
	left, right := net.Pipe()
	return NewConn(left), NewConn(right)
}
