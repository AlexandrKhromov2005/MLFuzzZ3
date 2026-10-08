//go:build !linux

package ipc

import (
	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// writeChannelEnvelope on non-Linux platforms supports only the
// plain (fd == -1) path. Any fd >= 0 yields
// ErrSCMRightsRequiresUnixConn since SCM_RIGHTS is not
// available outside Linux per ADR 0005 (Linux-only baseline).
func writeChannelEnvelope(
	conn *Conn, env *ipcv1.Envelope, fd int,
) error {
	if fd < 0 {
		return conn.WriteEnvelope(env)
	}
	return ErrSCMRightsRequiresUnixConn
}

// readChannelEnvelopeMaybeFD on non-Linux platforms is plain
// ReadEnvelope; no fds can be received.
func readChannelEnvelopeMaybeFD(
	conn *Conn,
) (*ipcv1.Envelope, int, error) {
	env, err := conn.ReadEnvelope()
	if err != nil {
		return nil, -1, err
	}
	return env, -1, nil
}

// closeReceivedFD on non-Linux is a no-op: no fd can have been
// received via SCM_RIGHTS in the first place.
func closeReceivedFD(_ int) {
}
