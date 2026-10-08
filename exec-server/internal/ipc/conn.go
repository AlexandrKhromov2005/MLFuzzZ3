package ipc

import (
	"fmt"
	"io"
	"sync"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// ErrConnClosed is returned by Read/Write after Close has been
// called. It wraps io.ErrClosedPipe for compatibility with
// existing Go idioms.
var ErrConnClosed = fmt.Errorf(
	"ipc: connection closed: %w", io.ErrClosedPipe)

// Conn wraps an io.ReadWriteCloser and provides envelope-level
// read and write operations. Framing details (length prefix,
// size limits) are delegated to WriteFrame/ReadFrame. Conn does
// not implement any protocol state machine; use ClientSession
// or ServerSession for that.
//
// Conn is safe for concurrent use: one goroutine may read while
// another writes. Concurrent readers or concurrent writers are
// not supported (serialize externally).
type Conn struct {
	rw io.ReadWriteCloser

	// Separate mutexes: readers and writers never contend,
	// which matches stream-socket semantics.
	readMu  sync.Mutex
	writeMu sync.Mutex

	closeMu sync.Mutex
	closed  bool
}

// NewConn wraps rw as a Conn. The caller retains ownership of rw
// only until Close is called on Conn — once closed, rw is also
// closed.
func NewConn(rw io.ReadWriteCloser) *Conn {
	return &Conn{rw: rw}
}

// WriteEnvelope marshals env and writes it as one framed message
// to the underlying stream. Returns ErrConnClosed if Close was
// previously called.
func (c *Conn) WriteEnvelope(env *ipcv1.Envelope) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.isClosed() {
		return ErrConnClosed
	}
	return WriteFrame(c.rw, env)
}

// ReadEnvelope reads one framed message and unmarshals it into
// an Envelope. Returns ErrConnClosed if Close was called.
// io.EOF on clean peer close is propagated as-is so callers can
// distinguish graceful shutdown.
func (c *Conn) ReadEnvelope() (*ipcv1.Envelope, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.isClosed() {
		return nil, ErrConnClosed
	}
	return ReadFrame(c.rw)
}

// Close closes the underlying stream. Subsequent Read/Write
// calls return ErrConnClosed. Calling Close multiple times is
// safe.
func (c *Conn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	return c.rw.Close()
}

func (c *Conn) isClosed() bool {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.closed
}
