package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// Protocol version this implementation speaks (ADR 0004).
const (
	ProtocolVersionMajor uint32 = 1
	ProtocolVersionMinor uint32 = 0
)

// ErrVersionMismatch is returned when peer reports a major
// version different from ours. Per ADR 0004 both sides must
// abort; this error surfaces that decision to the caller.
var ErrVersionMismatch = errors.New(
	"ipc: protocol major version mismatch")

// ErrUnexpectedEnvelope is returned when a peer's message does
// not fit the current state (e.g. RunResponse before init).
var ErrUnexpectedEnvelope = errors.New(
	"ipc: unexpected envelope payload for current session state")

// ErrSCMRightsRequiresUnixConn is returned when an attempt is
// made to transmit a ChannelAnnouncement with an attached fd
// over a transport that is not a Unix socket (for example
// net.Pipe used in tests, or any non-Linux platform). Per
// ADR 0015, SCM_RIGHTS is the only fd-passing mechanism
// supported, and it requires *net.UnixConn.
var ErrSCMRightsRequiresUnixConn = errors.New(
	"ipc: SCM_RIGHTS requires *net.UnixConn transport")

// ClientSession drives the client side of the IPC state machine
// (ADR 0004 Connection lifecycle, steps 2, 4, 5, 6 as seen by
// client). Constructed via Dial on a pre-established Conn.
type ClientSession struct {
	conn  *Conn
	ready bool
}

// DialResult is the outcome of the initial handshake + channel
// setup. If err is nil, the session is ready to Run.
type DialResult struct {
	Session *ClientSession
	Err     error
}

// ClientConfig controls the client handshake.
type ClientConfig struct {
	// RunTimeoutMs is the session-wide per-run timeout sent to
	// the server in InitRequest.
	RunTimeoutMs uint64

	// ExpectedChannels is the number of ChannelAnnouncement
	// messages the client expects from the server between Init
	// and the run loop. In Phase 1 this is 0 or 1 (edge only).
	ExpectedChannels int
}

// Dial performs the InitRequest/Response handshake and the
// ChannelAnnouncement exchanges on conn. On success the
// returned session is ready for Run.
//
// Per ADR 0015, when conn's underlying transport is a Unix
// socket each announcement may carry a file descriptor via
// SCM_RIGHTS. Phase 1 baseline has no fd consumer; received
// fds are closed defensively by this loop.
func Dial(
	ctx context.Context,
	conn *Conn,
	cfg ClientConfig,
) (*ClientSession, error) {
	initReq := &ipcv1.Envelope{
		Payload: &ipcv1.Envelope_InitRequest{
			InitRequest: &ipcv1.InitRequest{
				ProtocolVersionMajor: ProtocolVersionMajor,
				ProtocolVersionMinor: ProtocolVersionMinor,
				RunTimeoutMs:         cfg.RunTimeoutMs,
			},
		},
	}
	if err := conn.WriteEnvelope(initReq); err != nil {
		return nil, fmt.Errorf("dial: send init: %w", err)
	}

	resp, err := conn.ReadEnvelope()
	if err != nil {
		return nil, fmt.Errorf("dial: read init response: %w", err)
	}
	initResp, ok := resp.Payload.(*ipcv1.Envelope_InitResponse)
	if !ok {
		return nil, fmt.Errorf("dial: %w (got %T)",
			ErrUnexpectedEnvelope, resp.Payload)
	}
	if initResp.InitResponse.ProtocolVersionMajor !=
		ProtocolVersionMajor {
		return nil, fmt.Errorf(
			"dial: server major %d, client %d: %w",
			initResp.InitResponse.ProtocolVersionMajor,
			ProtocolVersionMajor,
			ErrVersionMismatch)
	}

	// Consume N ChannelAnnouncement messages and ack each.
	// On a *net.UnixConn transport an attached fd may be
	// received; in Phase 1 baseline there is no consumer, so
	// any fd is closed defensively (Phase 1.5 will plumb it
	// through to a real mmap consumer).
	for i := 0; i < cfg.ExpectedChannels; i++ {
		announcement, fd, err := readChannelEnvelopeMaybeFD(conn)
		if err != nil {
			return nil, fmt.Errorf(
				"dial: read channel announcement %d: %w", i, err)
		}
		if _, ok := announcement.Payload.(*ipcv1.Envelope_ChannelAnnouncement); !ok {
			closeReceivedFD(fd)
			return nil, fmt.Errorf(
				"dial: channel %d: %w (got %T)",
				i, ErrUnexpectedEnvelope, announcement.Payload)
		}
		// TODO(Phase 1.5): plumb fd to caller (mmap consumer).
		// Baseline closes defensively to avoid leaks.
		closeReceivedFD(fd)
		ack := &ipcv1.Envelope{
			Payload: &ipcv1.Envelope_ChannelAnnouncementAck{
				ChannelAnnouncementAck: &ipcv1.ChannelAnnouncementAck{},
			},
		}
		if err := conn.WriteEnvelope(ack); err != nil {
			return nil, fmt.Errorf(
				"dial: send ack %d: %w", i, err)
		}
	}

	_ = ctx
	return &ClientSession{conn: conn, ready: true}, nil
}

// Run sends one RunRequest and waits for the matching
// RunResponse. Blocking; respects ctx for cancellation during
// the wait. Not safe for concurrent calls on the same
// session — serialize externally if needed.
func (s *ClientSession) Run(
	ctx context.Context,
	input []byte,
) (*ipcv1.RunResponse, error) {
	if !s.ready {
		return nil, fmt.Errorf("run: %w",
			ErrUnexpectedEnvelope)
	}

	req := &ipcv1.Envelope{
		Payload: &ipcv1.Envelope_RunRequest{
			RunRequest: &ipcv1.RunRequest{Input: input},
		},
	}
	if err := s.conn.WriteEnvelope(req); err != nil {
		return nil, fmt.Errorf("run: send: %w", err)
	}

	// TODO(Task 4c): plumb ctx into read for true cancellation.
	// For Task 4a, ReadEnvelope does not honor context — it
	// blocks until data arrives or the peer closes.
	_ = ctx

	resp, err := s.conn.ReadEnvelope()
	if err != nil {
		return nil, fmt.Errorf("run: read: %w", err)
	}
	rr, ok := resp.Payload.(*ipcv1.Envelope_RunResponse)
	if !ok {
		return nil, fmt.Errorf("run: %w (got %T)",
			ErrUnexpectedEnvelope, resp.Payload)
	}
	return rr.RunResponse, nil
}

// Shutdown sends ShutdownRequest and waits for ShutdownResponse.
// After return, the session is no longer usable.
func (s *ClientSession) Shutdown(ctx context.Context) error {
	_ = ctx

	req := &ipcv1.Envelope{
		Payload: &ipcv1.Envelope_ShutdownRequest{
			ShutdownRequest: &ipcv1.ShutdownRequest{},
		},
	}
	if err := s.conn.WriteEnvelope(req); err != nil {
		return fmt.Errorf("shutdown: send: %w", err)
	}

	resp, err := s.conn.ReadEnvelope()
	if err != nil {
		return fmt.Errorf("shutdown: read: %w", err)
	}
	if _, ok := resp.Payload.(*ipcv1.Envelope_ShutdownResponse); !ok {
		return fmt.Errorf("shutdown: %w (got %T)",
			ErrUnexpectedEnvelope, resp.Payload)
	}
	s.ready = false
	return nil
}

// Close terminates the underlying connection without graceful
// shutdown. Use for error paths; prefer Shutdown for normal
// termination.
func (s *ClientSession) Close() error {
	return s.conn.Close()
}

// RunHandler handles one RunRequest on the server and returns
// the response that should be sent to the client. If it
// returns an error, the server sends an IPC_ERROR response
// with the error string.
type RunHandler func(
	ctx context.Context,
	req *ipcv1.RunRequest,
) (*ipcv1.RunResponse, error)

// ServerConfig controls the server side of the handshake.
type ServerConfig struct {
	// Channels is the list of channel descriptors the server
	// announces after the handshake. In Phase 1 baseline this
	// is typically empty; Phase 1.5 will populate it with
	// fd-bearing entries. FD = -1 selects the plain envelope
	// path; FD >= 0 selects SCM_RIGHTS (Linux Unix-socket
	// transport only — see ADR 0015).
	Channels []ChannelWithFD
}

// ChannelWithFD pairs a ChannelAnnouncement with its associated
// file descriptor for SCM_RIGHTS transmission. FD = -1 means no
// fd attached (plain envelope path). On the server side the fd
// is borrowed: the caller retains ownership and must keep it
// valid for the duration of the session and close it when done
// (per ADR 0015 §D send-side semantics).
type ChannelWithFD struct {
	Announcement *ipcv1.ChannelAnnouncement
	FD           int
}

// Serve drives the server side of the IPC state machine on
// conn. It consumes one InitRequest, sends InitResponse,
// announces cfg.Channels, waits for one Ack per announcement,
// then loops RunRequest ↔ handler ↔ RunResponse until a
// ShutdownRequest arrives (clean) or the client disconnects
// (returns io.EOF or a wrapped network error).
//
// Serve owns conn from the moment it is called and closes it
// before returning.
func Serve(
	ctx context.Context,
	conn *Conn,
	cfg ServerConfig,
	handler RunHandler,
) error {
	defer func() { _ = conn.Close() }()

	// Expect InitRequest.
	initEnv, err := conn.ReadEnvelope()
	if err != nil {
		return fmt.Errorf("serve: read init: %w", err)
	}
	initReq, ok := initEnv.Payload.(*ipcv1.Envelope_InitRequest)
	if !ok {
		return fmt.Errorf("serve: %w (got %T)",
			ErrUnexpectedEnvelope, initEnv.Payload)
	}

	// Check version.
	if initReq.InitRequest.ProtocolVersionMajor !=
		ProtocolVersionMajor {
		// Reply with our version, then abort.
		_ = conn.WriteEnvelope(&ipcv1.Envelope{
			Payload: &ipcv1.Envelope_InitResponse{
				InitResponse: &ipcv1.InitResponse{
					ProtocolVersionMajor: ProtocolVersionMajor,
					ProtocolVersionMinor: ProtocolVersionMinor,
				},
			},
		})
		return fmt.Errorf(
			"serve: client major %d, server %d: %w",
			initReq.InitRequest.ProtocolVersionMajor,
			ProtocolVersionMajor,
			ErrVersionMismatch)
	}

	initResp := &ipcv1.Envelope{
		Payload: &ipcv1.Envelope_InitResponse{
			InitResponse: &ipcv1.InitResponse{
				ProtocolVersionMajor: ProtocolVersionMajor,
				ProtocolVersionMinor: ProtocolVersionMinor,
			},
		},
	}
	if err := conn.WriteEnvelope(initResp); err != nil {
		return fmt.Errorf("serve: send init response: %w", err)
	}

	// Send channel announcements; expect an ack for each. Per
	// ADR 0015, an entry with FD >= 0 is sent via sendmsg +
	// SCM_RIGHTS; FD == -1 uses the plain envelope path.
	for i, ch := range cfg.Channels {
		env := &ipcv1.Envelope{
			Payload: &ipcv1.Envelope_ChannelAnnouncement{
				ChannelAnnouncement: ch.Announcement,
			},
		}
		if err := writeChannelEnvelope(
			conn, env, ch.FD); err != nil {
			return fmt.Errorf(
				"serve: announce channel %d: %w", i, err)
		}
		ack, err := conn.ReadEnvelope()
		if err != nil {
			return fmt.Errorf(
				"serve: read ack %d: %w", i, err)
		}
		if _, ok := ack.Payload.(*ipcv1.Envelope_ChannelAnnouncementAck); !ok {
			return fmt.Errorf(
				"serve: ack %d: %w (got %T)",
				i, ErrUnexpectedEnvelope, ack.Payload)
		}
	}

	// Run loop.
	var runID uint64
	for {
		env, err := conn.ReadEnvelope()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.EOF
			}
			return fmt.Errorf(
				"serve: read in run loop: %w", err)
		}

		switch p := env.Payload.(type) {
		case *ipcv1.Envelope_ShutdownRequest:
			resp := &ipcv1.Envelope{
				Payload: &ipcv1.Envelope_ShutdownResponse{
					ShutdownResponse: &ipcv1.ShutdownResponse{},
				},
			}
			if err := conn.WriteEnvelope(resp); err != nil {
				return fmt.Errorf(
					"serve: send shutdown response: %w", err)
			}
			return nil

		case *ipcv1.Envelope_RunRequest:
			runID++
			resp, err := handler(ctx, p.RunRequest)
			if err != nil {
				resp = &ipcv1.RunResponse{
					Status:       ipcv1.ExecStatus_EXEC_STATUS_IPC_ERROR,
					ErrorMessage: err.Error(),
				}
			}
			resp.RunId = runID
			wrapped := &ipcv1.Envelope{
				Payload: &ipcv1.Envelope_RunResponse{
					RunResponse: resp,
				},
			}
			if err := conn.WriteEnvelope(wrapped); err != nil {
				return fmt.Errorf(
					"serve: send run response: %w", err)
			}

		default:
			return fmt.Errorf(
				"serve: run loop: %w (got %T)",
				ErrUnexpectedEnvelope, env.Payload)
		}
	}
}
