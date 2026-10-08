//go:build linux

package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"google.golang.org/protobuf/proto"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// ErrMissingFD is returned by ReadEnvelopeWithFD when the
// caller demanded an SCM_RIGHTS fd but the peer's recvmsg
// produced no control message. Protocol-level error per
// docs/IPC.md §7.2 and ADR 0015 §E.
var ErrMissingFD = errors.New(
	"ipc: expected fd via SCM_RIGHTS but none received")

// ErrUnexpectedFD is returned when an SCM_RIGHTS fd was
// received but the caller's announcement variant did not
// expect one. The errant fd is closed before this error is
// returned. Reserved for Phase 1.5 callers that must reject
// fds on non-fd-bearing variants. Protocol-level error per
// docs/IPC.md §7.2 and ADR 0015 §E.
var ErrUnexpectedFD = errors.New(
	"ipc: unexpected fd received via SCM_RIGHTS")

// WriteEnvelopeWithFD marshals env, prefixes it with a 4-byte
// little-endian length, and sends the resulting frame together
// with fd via a single sendmsg call carrying SCM_RIGHTS.
//
// fd is borrowed: the caller retains ownership and must keep
// it valid for the duration of this call (per ADR 0015 §D).
// MaxFrameSize and short-write invariants from WriteFrame are
// preserved.
func WriteEnvelopeWithFD(
	uc *net.UnixConn, env *ipcv1.Envelope, fd int,
) error {
	body, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("scmrights: marshal envelope: %w", err)
	}
	if len(body) > MaxFrameSize {
		return fmt.Errorf(
			"scmrights: body size %d exceeds MaxFrameSize %d: %w",
			len(body), MaxFrameSize, ErrFrameLengthTooBig)
	}

	frame := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)

	rights := syscall.UnixRights(fd)

	n, oobn, err := uc.WriteMsgUnix(frame, rights, nil)
	if err != nil {
		return fmt.Errorf("scmrights: sendmsg with fd: %w", err)
	}
	if n != len(frame) {
		return fmt.Errorf(
			"scmrights: short sendmsg payload: %d of %d bytes",
			n, len(frame))
	}
	if oobn != len(rights) {
		return fmt.Errorf(
			"scmrights: short sendmsg control: %d of %d bytes",
			oobn, len(rights))
	}
	return nil
}

// ReadEnvelopeWithFD reads exactly one length-prefixed envelope
// and the fd attached via SCM_RIGHTS in the same recvmsg.
// Returns ErrMissingFD if no fd was received. The returned fd
// is owned by the caller — close with syscall.Close when done.
//
// On envelope unmarshal failure with a successfully received
// fd, the function returns (nil, fd, err): the caller still
// owns fd and must close it (per ADR 0015 §D).
func ReadEnvelopeWithFD(
	uc *net.UnixConn,
) (*ipcv1.Envelope, int, error) {
	env, fd, err := readEnvelopeMaybeFDInternal(uc)
	if err != nil {
		// Body-read or unmarshal error — fd may still be open;
		// returning as-is per ADR 0015 §D recv-side semantics.
		return env, fd, err
	}
	if fd < 0 {
		return nil, -1, ErrMissingFD
	}
	return env, fd, nil
}

// ReadEnvelopeMaybeFD reads exactly one length-prefixed
// envelope. If a fd was attached via SCM_RIGHTS it is
// returned; otherwise fd == -1 with err == nil. Used by Dial
// when an announcement variant may or may not be fd-bearing.
//
// Same ownership rules as ReadEnvelopeWithFD: caller must
// close any fd >= 0 returned.
func ReadEnvelopeMaybeFD(
	uc *net.UnixConn,
) (*ipcv1.Envelope, int, error) {
	return readEnvelopeMaybeFDInternal(uc)
}

func readEnvelopeMaybeFDInternal(
	uc *net.UnixConn,
) (*ipcv1.Envelope, int, error) {
	lenBuf := make([]byte, 4)
	oob := make([]byte, syscall.CmsgSpace(4))

	n, oobn, _, _, err := uc.ReadMsgUnix(lenBuf, oob)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, -1, io.EOF
		}
		return nil, -1, fmt.Errorf("scmrights: recvmsg prefix: %w", err)
	}

	fd := -1
	if oobn > 0 {
		parsedFD, perr := parseSingleFD(oob[:oobn])
		if perr != nil {
			return nil, -1, fmt.Errorf(
				"scmrights: parse cmsg: %w", perr)
		}
		fd = parsedFD
	}

	if n != 4 {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		return nil, -1, fmt.Errorf(
			"scmrights: short read for length prefix: %d of 4: %w",
			n, ErrFrameShortRead)
	}

	bodyLen := binary.LittleEndian.Uint32(lenBuf)
	if bodyLen > MaxFrameSize {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		return nil, -1, fmt.Errorf(
			"scmrights: length prefix %d exceeds MaxFrameSize %d: %w",
			bodyLen, MaxFrameSize, ErrFrameLengthTooBig)
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(uc, body); err != nil {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		if errors.Is(err, io.EOF) ||
			errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, -1, ErrFrameShortRead
		}
		return nil, -1, fmt.Errorf("scmrights: read body: %w", err)
	}

	env := &ipcv1.Envelope{}
	if err := proto.Unmarshal(body, env); err != nil {
		// Per ADR 0015 §D: fd is returned to caller for cleanup
		// even when the envelope failed to unmarshal.
		return nil, fd, fmt.Errorf(
			"scmrights: unmarshal envelope: %w", err)
	}
	return env, fd, nil
}

// parseSingleFD extracts exactly one fd from oob. Returns -1
// with no error if no fd is present in any cmsg. Returns an
// error if more than one fd is found, closing all collected
// fds defensively before returning.
func parseSingleFD(oob []byte) (int, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return -1, fmt.Errorf(
			"parse control message: %w", err)
	}
	var fds []int
	for i := range msgs {
		f, perr := syscall.ParseUnixRights(&msgs[i])
		if perr != nil {
			for _, fd := range fds {
				_ = syscall.Close(fd)
			}
			return -1, fmt.Errorf(
				"parse unix rights: %w", perr)
		}
		fds = append(fds, f...)
	}
	if len(fds) == 0 {
		return -1, nil
	}
	if len(fds) > 1 {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
		return -1, fmt.Errorf(
			"expected exactly 1 fd, got %d", len(fds))
	}
	return fds[0], nil
}

// writeChannelEnvelope is the bridge used by Serve to send one
// ChannelAnnouncement. fd == -1 selects the plain WriteEnvelope
// path. fd >= 0 requires the underlying transport to be a
// *net.UnixConn; otherwise ErrSCMRightsRequiresUnixConn is
// returned.
func writeChannelEnvelope(
	conn *Conn, env *ipcv1.Envelope, fd int,
) error {
	if fd < 0 {
		return conn.WriteEnvelope(env)
	}
	uc, ok := conn.rw.(*net.UnixConn)
	if !ok {
		return ErrSCMRightsRequiresUnixConn
	}
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	if conn.isClosed() {
		return ErrConnClosed
	}
	return WriteEnvelopeWithFD(uc, env, fd)
}

// readChannelEnvelopeMaybeFD is the bridge used by Dial to
// receive one ChannelAnnouncement. On a *net.UnixConn transport
// it uses recvmsg and may return an fd; on any other transport
// it falls back to ReadEnvelope and returns fd == -1.
func readChannelEnvelopeMaybeFD(
	conn *Conn,
) (*ipcv1.Envelope, int, error) {
	uc, ok := conn.rw.(*net.UnixConn)
	if !ok {
		env, err := conn.ReadEnvelope()
		if err != nil {
			return nil, -1, err
		}
		return env, -1, nil
	}
	conn.readMu.Lock()
	defer conn.readMu.Unlock()
	if conn.isClosed() {
		return nil, -1, ErrConnClosed
	}
	return readEnvelopeMaybeFDInternal(uc)
}

// closeReceivedFD closes a fd previously returned by
// readChannelEnvelopeMaybeFD or ReadEnvelopeMaybeFD. Safe to
// call with fd < 0 (no-op). Errors are swallowed: this is a
// cleanup path.
func closeReceivedFD(fd int) {
	if fd < 0 {
		return
	}
	_ = syscall.Close(fd)
}
