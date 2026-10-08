package ipc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// TestConnWriteReadRoundTrip: Write envelope on one side of
// net.Pipe, Read on the other.
func TestConnWriteReadRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()

	ca := NewConn(left)
	cb := NewConn(right)

	orig := &ipcv1.Envelope{
		Payload: &ipcv1.Envelope_RunRequest{
			RunRequest: &ipcv1.RunRequest{
				Input: []byte("hello"),
			},
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- ca.WriteEnvelope(orig)
	}()

	got, err := cb.ReadEnvelope()
	if err != nil {
		t.Fatalf("ReadEnvelope: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}

	rr, ok := got.Payload.(*ipcv1.Envelope_RunRequest)
	if !ok {
		t.Fatalf("wrong payload: %T", got.Payload)
	}
	if !bytes.Equal(rr.RunRequest.Input, []byte("hello")) {
		t.Errorf("payload mismatch: %x", rr.RunRequest.Input)
	}
}

// TestConnCloseErrConnClosed: Close on one side surfaces
// as an error on the other, and as ErrConnClosed on
// subsequent reads/writes after own Close.
func TestConnCloseErrConnClosed(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = right.Close() }()

	c := NewConn(left)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err := c.ReadEnvelope()
	if !errors.Is(err, ErrConnClosed) {
		t.Errorf("ReadEnvelope after close: expected "+
			"ErrConnClosed, got %v", err)
	}

	err = c.WriteEnvelope(&ipcv1.Envelope{})
	if !errors.Is(err, ErrConnClosed) {
		t.Errorf("WriteEnvelope after close: expected "+
			"ErrConnClosed, got %v", err)
	}
}

// TestConnPeerCloseReturnsEOF: When the peer cleanly closes,
// Read returns io.EOF (not wrapped).
func TestConnPeerCloseReturnsEOF(t *testing.T) {
	left, right := net.Pipe()
	ca := NewConn(left)
	cb := NewConn(right)

	if err := ca.Close(); err != nil {
		t.Fatalf("ca.Close: %v", err)
	}

	_, err := cb.ReadEnvelope()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got %v", err)
	}
	_ = cb.Close()
}
