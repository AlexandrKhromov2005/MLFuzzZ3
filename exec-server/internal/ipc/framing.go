package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// MaxFrameSize is the hard upper bound on a single framed protobuf
// message. Frames with a length prefix exceeding this value are
// treated as a corrupted stream per ADR 0004. See also the framing
// section of that ADR for the wire format specification.
const MaxFrameSize = 1 << 20 // 1 MiB

// ErrFrameLengthTooBig is returned by ReadFrame when the 4-byte
// length prefix decodes to a value greater than MaxFrameSize.
// Callers should treat this as a fatal protocol error — the stream
// cannot be recovered, the connection must be closed.
var ErrFrameLengthTooBig = errors.New(
	"framing: length prefix exceeds 1 MiB")

// ErrFrameShortRead is returned by ReadFrame when the connection
// closes partway through a frame — for example, after the length
// prefix has been read but before all body bytes have arrived.
// Distinguished from io.EOF (clean close before any bytes of the
// next frame) because short-read typically indicates a worker
// crash, whereas clean EOF indicates ordinary session shutdown.
var ErrFrameShortRead = errors.New(
	"framing: short read (connection closed mid-frame)")

// WriteFrame serializes env and writes it to w as a length-prefixed
// frame: [4-byte little-endian length][body]. The length prefix is
// the exact size of the serialized body in bytes; bodies larger
// than MaxFrameSize are rejected without writing anything.
//
// WriteFrame does not buffer — every call issues exactly one write
// to w. For stream-socket writers this means the length prefix and
// body may arrive as separate TCP segments; that is acceptable for
// our transport (stream-mode Unix domain socket).
func WriteFrame(w io.Writer, env *ipcv1.Envelope) error {
	body, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("framing: marshal envelope: %w", err)
	}
	if len(body) > MaxFrameSize {
		return fmt.Errorf(
			"framing: body size %d exceeds MaxFrameSize %d: %w",
			len(body), MaxFrameSize, ErrFrameLengthTooBig)
	}

	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(body)))

	// Single write of header + body to minimize packet
	// fragmentation. Acceptable for typical message sizes
	// (< 1 MiB); not appropriate for streaming.
	frame := make([]byte, 4+len(body))
	copy(frame[0:4], header[:])
	copy(frame[4:], body)

	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("framing: write frame: %w", err)
	}
	return nil
}

// ReadFrame reads exactly one length-prefixed frame from r and
// parses it as an Envelope.
//
// Return values:
//   - (env, nil) on success.
//   - (nil, io.EOF) if the connection was closed cleanly before
//     any bytes of the next frame were read. Callers should
//     interpret this as graceful session shutdown.
//   - (nil, ErrFrameShortRead) if the connection closed partway
//     through the frame. Callers should treat as unexpected
//     disconnect.
//   - (nil, ErrFrameLengthTooBig) if the length prefix exceeds
//     MaxFrameSize. Stream is corrupted; caller must close.
//   - (nil, err) wrapping any other I/O or unmarshal error.
func ReadFrame(r io.Reader) (*ipcv1.Envelope, error) {
	var header [4]byte
	n, err := io.ReadFull(r, header[:])
	if err != nil {
		// io.ReadFull returns io.EOF if zero bytes were read,
		// io.ErrUnexpectedEOF if some (but not all) bytes were
		// read. The first is a clean close; the second is a
		// mid-frame close which we map to ErrFrameShortRead.
		if errors.Is(err, io.EOF) && n == 0 {
			return nil, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrFrameShortRead
		}
		return nil, fmt.Errorf("framing: read header: %w", err)
	}

	length := binary.LittleEndian.Uint32(header[:])
	if length > MaxFrameSize {
		return nil, fmt.Errorf(
			"framing: length prefix %d exceeds MaxFrameSize %d: %w",
			length, MaxFrameSize, ErrFrameLengthTooBig)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) ||
			errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrFrameShortRead
		}
		return nil, fmt.Errorf("framing: read body: %w", err)
	}

	env := &ipcv1.Envelope{}
	if err := proto.Unmarshal(body, env); err != nil {
		return nil, fmt.Errorf("framing: unmarshal envelope: %w", err)
	}
	return env, nil
}
