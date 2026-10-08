package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// TestWriteReadRoundTrip is the happiest path: write one frame,
// read it back, verify the payload round-trips byte-for-byte.
func TestWriteReadRoundTrip(t *testing.T) {
	orig := &ipcv1.Envelope{
		Payload: &ipcv1.Envelope_InitRequest{
			InitRequest: &ipcv1.InitRequest{
				ProtocolVersionMajor: 1,
				ProtocolVersionMinor: 0,
				RunTimeoutMs:         500,
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, orig); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	init, ok := got.Payload.(*ipcv1.Envelope_InitRequest)
	if !ok {
		t.Fatalf("unexpected payload type: %T", got.Payload)
	}
	if init.InitRequest.ProtocolVersionMajor != 1 ||
		init.InitRequest.ProtocolVersionMinor != 0 ||
		init.InitRequest.RunTimeoutMs != 500 {
		t.Errorf("payload mismatch: %+v", init.InitRequest)
	}
}

// TestWriteReadMultipleFrames ensures framing lets us pack and
// unpack several frames in sequence from a single stream.
func TestWriteReadMultipleFrames(t *testing.T) {
	inputs := [][]byte{
		[]byte("first"),
		[]byte("second message is longer"),
		[]byte(""),
		{0x00, 0xff, 0x42},
	}

	var buf bytes.Buffer
	for _, in := range inputs {
		env := &ipcv1.Envelope{
			Payload: &ipcv1.Envelope_RunRequest{
				RunRequest: &ipcv1.RunRequest{Input: in},
			},
		}
		if err := WriteFrame(&buf, env); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}

	for i, want := range inputs {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		rr, ok := got.Payload.(*ipcv1.Envelope_RunRequest)
		if !ok {
			t.Fatalf(
				"frame %d: unexpected payload type: %T",
				i, got.Payload)
		}
		if !bytes.Equal(rr.RunRequest.Input, want) {
			t.Errorf(
				"frame %d: got %x want %x",
				i, rr.RunRequest.Input, want)
		}
	}
}

// TestReadFrameCleanEOF: reading from an empty stream returns
// io.EOF (clean close, no bytes consumed). Caller should treat
// as graceful shutdown.
func TestReadFrameCleanEOF(t *testing.T) {
	var empty bytes.Buffer
	_, err := ReadFrame(&empty)
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

// TestReadFrameShortHeader: stream ends partway through the 4-byte
// length prefix. Caller should get ErrFrameShortRead (not io.EOF,
// because some bytes arrived before close).
func TestReadFrameShortHeader(t *testing.T) {
	partial := bytes.NewBuffer([]byte{0x01, 0x02}) // 2 bytes, not 4
	_, err := ReadFrame(partial)
	if !errors.Is(err, ErrFrameShortRead) {
		t.Errorf("expected ErrFrameShortRead, got %v", err)
	}
}

// TestReadFrameShortBody: length prefix says 100 bytes but only 5
// arrive before close. Same expected behavior as short header.
func TestReadFrameShortBody(t *testing.T) {
	var buf bytes.Buffer
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], 100)
	buf.Write(header[:])
	buf.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0x00}) // 5 < 100

	_, err := ReadFrame(&buf)
	if !errors.Is(err, ErrFrameShortRead) {
		t.Errorf("expected ErrFrameShortRead, got %v", err)
	}
}

// TestReadFrameLengthTooBig: length prefix of 0xFFFFFFFF (4 GiB)
// must be rejected without attempting to allocate.
func TestReadFrameLengthTooBig(t *testing.T) {
	var buf bytes.Buffer
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], 0xFFFFFFFF)
	buf.Write(header[:])
	// No body — the test is that ReadFrame rejects before it
	// tries to allocate/read body.

	_, err := ReadFrame(&buf)
	if !errors.Is(err, ErrFrameLengthTooBig) {
		t.Errorf("expected ErrFrameLengthTooBig, got %v", err)
	}
}

// TestWriteFrameOversizedBody: if the caller supplies an Envelope
// whose serialized form exceeds MaxFrameSize, WriteFrame must
// refuse before issuing any I/O. We construct an oversized
// RunRequest input to trigger this.
func TestWriteFrameOversizedBody(t *testing.T) {
	oversized := make([]byte, MaxFrameSize+1)
	env := &ipcv1.Envelope{
		Payload: &ipcv1.Envelope_RunRequest{
			RunRequest: &ipcv1.RunRequest{Input: oversized},
		},
	}

	var buf bytes.Buffer
	err := WriteFrame(&buf, env)
	if !errors.Is(err, ErrFrameLengthTooBig) {
		t.Errorf("expected ErrFrameLengthTooBig, got %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf(
			"WriteFrame wrote %d bytes on error (expected 0)",
			buf.Len())
	}
}
