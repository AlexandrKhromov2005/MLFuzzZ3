//go:build linux && amd64

package ipc

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"google.golang.org/protobuf/proto"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

const memfdContent = "scm-rights-go-test-payload"

// sysMemfdCreate is the memfd_create(2) syscall number on
// linux/amd64. The stdlib syscall package does not export this
// constant in Go 1.23, and pulling in golang.org/x/sys/unix
// would require a new dependency ADR (project conventions). The
// build tag restricts this test file to linux/amd64, which is
// the Phase 1 baseline architecture.
const sysMemfdCreate = 319

// memfdCreate wraps the memfd_create(2) syscall using the
// hardcoded x86_64 syscall number above.
func memfdCreate(name string) (int, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	fd, _, errno := syscall.Syscall(
		sysMemfdCreate,
		uintptr(unsafe.Pointer(namePtr)),
		0,
		0,
	)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// socketpairUnix returns two connected *net.UnixConn endpoints
// backed by an AF_UNIX SOCK_STREAM socketpair. Cleanup is
// registered via t.Cleanup.
func socketpairUnix(
	t *testing.T,
) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(
		syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}

	a := os.NewFile(uintptr(fds[0]), "sp-a")
	b := os.NewFile(uintptr(fds[1]), "sp-b")

	ucA, err := net.FileConn(a)
	_ = a.Close()
	if err != nil {
		_ = b.Close()
		t.Fatalf("FileConn a: %v", err)
	}
	ucB, err := net.FileConn(b)
	_ = b.Close()
	if err != nil {
		_ = ucA.Close()
		t.Fatalf("FileConn b: %v", err)
	}

	ucAUnix, ok := ucA.(*net.UnixConn)
	if !ok {
		_ = ucA.Close()
		_ = ucB.Close()
		t.Fatalf("conn a is %T, want *net.UnixConn", ucA)
	}
	ucBUnix, ok := ucB.(*net.UnixConn)
	if !ok {
		_ = ucA.Close()
		_ = ucB.Close()
		t.Fatalf("conn b is %T, want *net.UnixConn", ucB)
	}

	t.Cleanup(func() {
		_ = ucAUnix.Close()
		_ = ucBUnix.Close()
	})
	return ucAUnix, ucBUnix
}

// edgeAnnouncementEnv builds an Envelope wrapping an Edge
// ChannelAnnouncement, used as the round-trip payload.
func edgeAnnouncementEnv() *ipcv1.Envelope {
	return &ipcv1.Envelope{
		Payload: &ipcv1.Envelope_ChannelAnnouncement{
			ChannelAnnouncement: &ipcv1.ChannelAnnouncement{
				Descriptor_: &ipcv1.ChannelAnnouncement_Edge{
					Edge: &ipcv1.EdgeCoverageDescriptor{
						ShmName:       "edge-test",
						Offset:        0,
						Length:        4096,
						SchemaVersion: 1,
					},
				},
			},
		},
	}
}

// writePlainFrame writes a length-prefixed envelope to uc using
// plain Write (no SCM_RIGHTS). Used by tests that exercise the
// receiver's behaviour when no cmsg is present.
func writePlainFrame(
	t *testing.T, uc *net.UnixConn, env *ipcv1.Envelope,
) {
	t.Helper()
	body, err := proto.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	frame := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	if _, err := uc.Write(frame); err != nil {
		t.Fatalf("write plain frame: %v", err)
	}
}

// TestSCMRightsRoundTrip: server creates a memfd, writes known
// content, sends ChannelAnnouncement with that fd via
// WriteEnvelopeWithFD; client reads via ReadEnvelopeWithFD,
// mmaps the received fd, and verifies the content matches.
func TestSCMRightsRoundTrip(t *testing.T) {
	ucServer, ucClient := socketpairUnix(t)

	sendFD, err := memfdCreate("test-roundtrip")
	if err != nil {
		t.Fatalf("memfdCreate: %v", err)
	}
	defer func() { _ = syscall.Close(sendFD) }()

	if _, err := syscall.Write(
		sendFD, []byte(memfdContent)); err != nil {
		t.Fatalf("write to memfd: %v", err)
	}

	env := edgeAnnouncementEnv()
	if err := WriteEnvelopeWithFD(
		ucServer, env, sendFD); err != nil {
		t.Fatalf("WriteEnvelopeWithFD: %v", err)
	}

	gotEnv, recvFD, err := ReadEnvelopeWithFD(ucClient)
	if err != nil {
		t.Fatalf("ReadEnvelopeWithFD: %v", err)
	}
	defer func() { _ = syscall.Close(recvFD) }()

	if recvFD < 0 {
		t.Fatalf("recvFD invalid: %d", recvFD)
	}
	if recvFD == sendFD {
		t.Errorf(
			"recvFD %d aliases sendFD %d (kernel must dup)",
			recvFD, sendFD)
	}

	ann, ok := gotEnv.Payload.(*ipcv1.Envelope_ChannelAnnouncement)
	if !ok {
		t.Fatalf("got payload %T, want ChannelAnnouncement",
			gotEnv.Payload)
	}
	edge := ann.ChannelAnnouncement.GetEdge()
	if edge == nil {
		t.Fatalf("Edge descriptor missing")
	}
	if edge.ShmName != "edge-test" {
		t.Errorf("ShmName = %q, want %q",
			edge.ShmName, "edge-test")
	}

	data, err := syscall.Mmap(
		recvFD, 0, len(memfdContent),
		syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	defer func() { _ = syscall.Munmap(data) }()

	if string(data) != memfdContent {
		t.Errorf("mmap content = %q, want %q",
			string(data), memfdContent)
	}
}

// TestReadEnvelopeWithFDMissingErr: peer sends a plain envelope
// (no SCM_RIGHTS). ReadEnvelopeWithFD must return ErrMissingFD.
func TestReadEnvelopeWithFDMissingErr(t *testing.T) {
	ucServer, ucClient := socketpairUnix(t)

	writePlainFrame(t, ucServer, edgeAnnouncementEnv())

	gotEnv, fd, err := ReadEnvelopeWithFD(ucClient)
	if !errors.Is(err, ErrMissingFD) {
		t.Errorf("err = %v, want ErrMissingFD", err)
	}
	if gotEnv != nil {
		t.Errorf("env = %v, want nil", gotEnv)
	}
	if fd != -1 {
		_ = syscall.Close(fd)
		t.Errorf("fd = %d, want -1", fd)
	}
}

// TestReadEnvelopeMaybeFDPlain: peer sends a plain envelope.
// ReadEnvelopeMaybeFD must succeed with fd == -1 and no error.
func TestReadEnvelopeMaybeFDPlain(t *testing.T) {
	ucServer, ucClient := socketpairUnix(t)

	writePlainFrame(t, ucServer, edgeAnnouncementEnv())

	gotEnv, fd, err := ReadEnvelopeMaybeFD(ucClient)
	if err != nil {
		t.Fatalf("ReadEnvelopeMaybeFD: %v", err)
	}
	if fd != -1 {
		_ = syscall.Close(fd)
		t.Errorf("fd = %d, want -1 on plain envelope", fd)
	}
	if gotEnv == nil {
		t.Fatalf("env = nil")
	}
	if _, ok := gotEnv.Payload.(*ipcv1.Envelope_ChannelAnnouncement); !ok {
		t.Errorf("payload type = %T, want ChannelAnnouncement",
			gotEnv.Payload)
	}
}

// TestReadEnvelopeWithFDUnmarshalFailureReturnsFD: peer sends a
// valid fd via SCM_RIGHTS but a corrupt body. ReadEnvelopeWithFD
// must return (nil, fd>=0, err) so the caller can close fd
// (per ADR 0015 §D).
func TestReadEnvelopeWithFDUnmarshalFailureReturnsFD(
	t *testing.T,
) {
	ucServer, ucClient := socketpairUnix(t)

	sendFD, err := memfdCreate("test-bad-body")
	if err != nil {
		t.Fatalf("memfdCreate: %v", err)
	}
	defer func() { _ = syscall.Close(sendFD) }()

	garbage := []byte{0xff, 0xff, 0xff, 0xff, 0xff}
	frame := make([]byte, 4+len(garbage))
	binary.LittleEndian.PutUint32(
		frame[:4], uint32(len(garbage)))
	copy(frame[4:], garbage)

	rights := syscall.UnixRights(sendFD)
	if _, _, err := ucServer.WriteMsgUnix(
		frame, rights, nil); err != nil {
		t.Fatalf("WriteMsgUnix: %v", err)
	}

	gotEnv, recvFD, err := ReadEnvelopeWithFD(ucClient)
	if err == nil {
		if recvFD >= 0 {
			_ = syscall.Close(recvFD)
		}
		t.Fatalf("expected unmarshal error, got nil")
	}
	if gotEnv != nil {
		t.Errorf("env = %v, want nil", gotEnv)
	}
	if recvFD < 0 {
		t.Fatalf("fd not returned for cleanup: %d", recvFD)
	}
	defer func() { _ = syscall.Close(recvFD) }()

	var stat syscall.Stat_t
	if err := syscall.Fstat(recvFD, &stat); err != nil {
		t.Errorf("fstat on returned fd: %v", err)
	}
}

// TestServeRequiresUnixConnForFD: Serve invoked over a net.Pipe
// transport with a Channel that has FD >= 0 must surface
// ErrSCMRightsRequiresUnixConn after the init handshake. Drives
// the client side just far enough to advance the server into
// the announce loop.
func TestServeRequiresUnixConnForFD(t *testing.T) {
	clientConn, serverConn := pipeConns()
	defer func() { _ = clientConn.Close() }()

	ann := &ipcv1.ChannelAnnouncement{
		Descriptor_: &ipcv1.ChannelAnnouncement_Edge{
			Edge: &ipcv1.EdgeCoverageDescriptor{
				ShmName:       "edge-test",
				Offset:        0,
				Length:        4096,
				SchemaVersion: 1,
			},
		},
	}

	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer func() { _ = devnull.Close() }()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- Serve(
			context.Background(),
			serverConn,
			ServerConfig{
				Channels: []ChannelWithFD{
					{
						Announcement: ann,
						FD:           int(devnull.Fd()),
					},
				},
			},
			echoHandler,
		)
	}()

	initReq := &ipcv1.Envelope{
		Payload: &ipcv1.Envelope_InitRequest{
			InitRequest: &ipcv1.InitRequest{
				ProtocolVersionMajor: ProtocolVersionMajor,
				ProtocolVersionMinor: ProtocolVersionMinor,
				RunTimeoutMs:         500,
			},
		},
	}
	if err := clientConn.WriteEnvelope(initReq); err != nil {
		t.Fatalf("client write init: %v", err)
	}
	if _, err := clientConn.ReadEnvelope(); err != nil {
		t.Fatalf("client read init response: %v", err)
	}

	select {
	case serveErr := <-serverErrCh:
		if !errors.Is(
			serveErr, ErrSCMRightsRequiresUnixConn) {
			t.Errorf(
				"Serve err = %v, want wrap of "+
					"ErrSCMRightsRequiresUnixConn",
				serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within 2s")
	}
}
