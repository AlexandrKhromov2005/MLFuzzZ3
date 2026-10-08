package coverage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// MapSize is the coverage bitmap size in bytes — 64 KiB.
// Matches COV_MAP_SIZE in src/runtime/coverage/mlfuzzz3_cov.c
// (ADR 0017).
const MapSize = 1 << 16

// schemaVersion is the EdgeCoverageDescriptor schema_version
// field. Stage 1 = 1; bumps when the bitmap layout changes
// in incompatible ways.
const schemaVersion uint32 = 1

// shmName advertised in EdgeCoverageDescriptor. Cosmetic
// identifier — peer treats it as opaque label.
const shmName = "coverage-edges"

// Channel owns a memfd-backed coverage bitmap shared with
// the target process via fd inheritance + LD_PRELOAD library.
// Per ADR 0033 it also owns a second, independent memfd for the
// branch-value channel (separate segment, separate descriptor); the
// edge bitmap above remains the single source of truth for coverage.
type Channel struct {
	fd      int
	memfd   *os.File
	buf     []byte
	libPath string

	// Branch-value channel (ADR 0033): a separate SHM segment the
	// runtime fills with one record per executed icmp. Independent of
	// the edge bitmap; nil branchBuf means the channel is closed.
	branchFd    int
	branchMemfd *os.File
	branchBuf   []byte
	// index is the position in the parent ChannelSet's
	// Channels()/Announcements() slice. Set by ChannelSet
	// during construction. Standalone Channels (created
	// via NewChannel directly) have index = -1, signaling
	// "not part of a multi-channel set" (ADR 0019 Task 8c).
	index int
}

// NewChannel creates a 64 KiB memfd, mmaps it read+write,
// and returns a Channel wrapping the result. libPath must
// be an absolute path to a regular file (the LD_PRELOAD
// coverage library); validation runs before any syscall.
func NewChannel(libPath string) (*Channel, error) {
	if !filepath.IsAbs(libPath) {
		return nil, fmt.Errorf(
			"coverage library path must be absolute: %q",
			libPath)
	}
	info, err := os.Stat(libPath)
	if err != nil {
		return nil, fmt.Errorf(
			"coverage library stat: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"coverage library is not a regular file: %q",
			libPath)
	}

	fd, err := memfdCreate("mlfuzzz3-cov")
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	if err := syscall.Ftruncate(fd, MapSize); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("ftruncate: %w", err)
	}
	buf, err := syscall.Mmap(
		fd, 0, MapSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("mmap: %w", err)
	}

	// Branch-value channel: a second, independent memfd (ADR 0033).
	// On any failure here the edge memfd above is unwound too.
	branchFd, branchBuf, err := newBranchSegment()
	if err != nil {
		_ = syscall.Munmap(buf)
		_ = syscall.Close(fd)
		return nil, err
	}

	return &Channel{
		fd:          fd,
		memfd:       os.NewFile(uintptr(fd), "mlfuzzz3-cov"),
		buf:         buf,
		libPath:     libPath,
		index:       -1, // standalone; ChannelSet overrides.
		branchFd:    branchFd,
		branchMemfd: os.NewFile(uintptr(branchFd), "mlfuzzz3-branch"),
		branchBuf:   branchBuf,
	}, nil
}

// newBranchSegment creates, sizes and maps a branch-value memfd. The
// segment is BranchSegmentSize bytes; the runtime derives its record
// capacity from that size at startup.
func newBranchSegment() (int, []byte, error) {
	fd, err := memfdCreate("mlfuzzz3-branch")
	if err != nil {
		return -1, nil, fmt.Errorf("memfd_create (branch): %w", err)
	}
	if err := syscall.Ftruncate(fd, BranchSegmentSize); err != nil {
		_ = syscall.Close(fd)
		return -1, nil, fmt.Errorf("ftruncate (branch): %w", err)
	}
	buf, err := syscall.Mmap(
		fd, 0, BranchSegmentSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED)
	if err != nil {
		_ = syscall.Close(fd)
		return -1, nil, fmt.Errorf("mmap (branch): %w", err)
	}
	return fd, buf, nil
}

// FD returns the raw file descriptor. Borrowed — Channel
// retains ownership; caller must not close.
func (c *Channel) FD() int { return c.fd }

// MemfdFile returns the *os.File wrapping the memfd, suitable
// for cmd.ExtraFiles. Borrowed; caller must not close.
func (c *Channel) MemfdFile() *os.File { return c.memfd }

// LibPath returns the absolute path to the LD_PRELOAD
// coverage library.
func (c *Channel) LibPath() string { return c.libPath }

// Announcement returns the ChannelAnnouncement descriptor
// suitable for ServerConfig.Channels. Always edge-variant
// for Stage 1.
func (c *Channel) Announcement() *ipcv1.ChannelAnnouncement {
	return &ipcv1.ChannelAnnouncement{
		Descriptor_: &ipcv1.ChannelAnnouncement_Edge{
			Edge: &ipcv1.EdgeCoverageDescriptor{
				ShmName:       shmName,
				Offset:        0,
				Length:        MapSize,
				SchemaVersion: schemaVersion,
			},
		},
	}
}

// Reset zeroes the bitmap. Per ADR 0018 lifecycle — must
// be called before each Run dispatch, before target spawn.
// Concurrent with target writes is undefined per ADR 0018
// open-question handling (sequential per-Run lifecycle).
func (c *Channel) Reset() error {
	if c.buf == nil {
		return errors.New("coverage channel closed")
	}
	for i := range c.buf {
		c.buf[i] = 0
	}
	return nil
}

// Read returns a copy of the bitmap. Allocates new
// []byte each call (64 KiB). Caller-supplied buffer
// optimization — Phase 2 concern.
func (c *Channel) Read() ([]byte, error) {
	if c.buf == nil {
		return nil, errors.New("coverage channel closed")
	}
	out := make([]byte, len(c.buf))
	copy(out, c.buf)
	return out, nil
}

// Index returns this channel's position in the parent
// ChannelSet's slice, or -1 if the channel is standalone
// (created via NewChannel directly rather than through
// NewChannelSet). Per ADR 0019 Task 8c.
func (c *Channel) Index() int { return c.index }

// BranchFD returns the raw branch-segment file descriptor. Borrowed —
// Channel retains ownership; caller must not close.
func (c *Channel) BranchFD() int { return c.branchFd }

// BranchMemfdFile returns the *os.File wrapping the branch memfd,
// suitable for cmd.ExtraFiles. Borrowed; caller must not close.
func (c *Channel) BranchMemfdFile() *os.File { return c.branchMemfd }

// BranchAnnouncement returns the ChannelAnnouncement carrying the
// branch-value descriptor (ADR 0033). Parallel to Announcement()
// (the edge variant); the matching memfd travels via SCM_RIGHTS.
func (c *Channel) BranchAnnouncement() *ipcv1.ChannelAnnouncement {
	return &ipcv1.ChannelAnnouncement{
		Descriptor_: &ipcv1.ChannelAnnouncement_Branch{
			Branch: &ipcv1.BranchValuesDescriptor{
				ShmName:       branchShmName,
				Offset:        0,
				Length:        BranchSegmentSize,
				SchemaVersion: branchSchemaVersion,
			},
		},
	}
}

// ResetBranch zeroes the branch segment. Must be called before each
// Run dispatch, before target spawn — same lifecycle as Reset() for
// the edge bitmap (the runtime re-initializes the header on startup,
// but zeroing keeps stale records from a prior run out of the buffer).
func (c *Channel) ResetBranch() error {
	if c.branchBuf == nil {
		return errors.New("branch channel closed")
	}
	for i := range c.branchBuf {
		c.branchBuf[i] = 0
	}
	return nil
}

// ReadBranchSummary returns the run-level summary the core needs: how
// many records the runtime appended this run and whether the segment
// overflowed. The records themselves are read out-of-band by the core
// from the announced memfd.
func (c *Channel) ReadBranchSummary() (count uint32, overflow bool, err error) {
	if c.branchBuf == nil {
		return 0, false, errors.New("branch channel closed")
	}
	count, overflow = parseBranchHeader(c.branchBuf)
	return count, overflow, nil
}

// ReadBranchRecords decodes the appended comparison records. Provided
// for in-process inspection/tests; the production read path uses only
// ReadBranchSummary (the core reads records directly from the SHM).
func (c *Channel) ReadBranchRecords() ([]BranchRecord, error) {
	if c.branchBuf == nil {
		return nil, errors.New("branch channel closed")
	}
	return parseBranchRecords(c.branchBuf), nil
}

// Close munmaps the buffers and closes the memfds (edge and branch).
// Idempotent.
func (c *Channel) Close() error {
	var firstErr error
	if c.buf != nil {
		if err := syscall.Munmap(c.buf); err != nil {
			firstErr = fmt.Errorf("munmap: %w", err)
		}
		c.buf = nil
	}
	if c.memfd != nil {
		if err := c.memfd.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close memfd: %w", err)
		}
		c.memfd = nil
		c.fd = -1
	}
	if c.branchBuf != nil {
		if err := syscall.Munmap(c.branchBuf); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("munmap branch: %w", err)
		}
		c.branchBuf = nil
	}
	if c.branchMemfd != nil {
		if err := c.branchMemfd.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close branch memfd: %w", err)
		}
		c.branchMemfd = nil
		c.branchFd = -1
	}
	return firstErr
}
