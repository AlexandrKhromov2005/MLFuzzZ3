//go:build linux

package coverage_test

import (
	"encoding/binary"
	"syscall"
	"testing"

	"mlfuzzz3/exec-server/internal/coverage"
)

// Branch-segment ABI offsets, mirrored from
// src/runtime/coverage/mlfuzzz3_branch.h. Re-declared here (not
// imported — they are unexported in the coverage package) so the test
// independently pins the layout the Channel parser must agree with.
const (
	tHeaderSize = 16
	tRecordSize = 24

	tOffCount    = 0
	tOffCapacity = 4
	tOffOverflow = 8

	tRecSiteID    = 0
	tRecPredicate = 4
	tRecBitWidth  = 5
	tRecLHS       = 8
	tRecRHS       = 16
)

type wantRecord struct {
	siteID    uint32
	predicate uint8
	bitWidth  uint8
	lhs       uint64
	rhs       uint64
}

// writeBranchSegment maps the branch fd independently and writes a
// header plus records at the canonical offsets. Pages are shared with
// the Channel's own mapping (both MAP_SHARED on the same memfd), so the
// Channel observes the writes.
func writeBranchSegment(t *testing.T, fd int, count, capacity uint32,
	overflow bool, recs []wantRecord) {
	t.Helper()
	m, err := syscall.Mmap(fd, 0, coverage.BranchSegmentSize,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap branch fd: %v", err)
	}
	defer func() {
		if uerr := syscall.Munmap(m); uerr != nil {
			t.Errorf("munmap: %v", uerr)
		}
	}()

	binary.LittleEndian.PutUint32(m[tOffCount:], count)
	binary.LittleEndian.PutUint32(m[tOffCapacity:], capacity)
	var ov uint32
	if overflow {
		ov = 1
	}
	binary.LittleEndian.PutUint32(m[tOffOverflow:], ov)

	for i, r := range recs {
		off := tHeaderSize + i*tRecordSize
		rec := m[off : off+tRecordSize]
		binary.LittleEndian.PutUint32(rec[tRecSiteID:], r.siteID)
		rec[tRecPredicate] = r.predicate
		rec[tRecBitWidth] = r.bitWidth
		binary.LittleEndian.PutUint64(rec[tRecLHS:], r.lhs)
		binary.LittleEndian.PutUint64(rec[tRecRHS:], r.rhs)
	}
}

func TestBranchAnnouncementDescriptor(t *testing.T) {
	ch, err := coverage.NewChannel(makeFakeLib(t))
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()

	ann := ch.BranchAnnouncement()
	if ann == nil {
		t.Fatal("BranchAnnouncement returned nil")
	}
	br := ann.GetBranch()
	if br == nil {
		t.Fatal("BranchAnnouncement.GetBranch() = nil")
	}
	if br.Length != coverage.BranchSegmentSize {
		t.Errorf("branch length = %d, want %d", br.Length,
			coverage.BranchSegmentSize)
	}
	if br.SchemaVersion != 1 {
		t.Errorf("branch schema_version = %d, want 1", br.SchemaVersion)
	}
	if br.ShmName == "" {
		t.Error("branch shm_name is empty")
	}
	if br.Offset != 0 {
		t.Errorf("branch offset = %d, want 0", br.Offset)
	}

	// The edge announcement must still be the edge variant — the two
	// channels are independent.
	if ch.Announcement().GetEdge() == nil {
		t.Error("edge Announcement().GetEdge() = nil after branch added")
	}
	if ch.BranchFD() < 0 {
		t.Errorf("BranchFD = %d, want >= 0", ch.BranchFD())
	}
	if ch.BranchMemfdFile() == nil {
		t.Error("BranchMemfdFile returned nil")
	}
}

func TestBranchFreshSegmentIsEmpty(t *testing.T) {
	ch, err := coverage.NewChannel(makeFakeLib(t))
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()

	if err := ch.ResetBranch(); err != nil {
		t.Fatalf("ResetBranch: %v", err)
	}
	count, overflow, err := ch.ReadBranchSummary()
	if err != nil {
		t.Fatalf("ReadBranchSummary: %v", err)
	}
	if count != 0 || overflow {
		t.Errorf("fresh segment summary = (%d, %v), want (0, false)",
			count, overflow)
	}
	recs, err := ch.ReadBranchRecords()
	if err != nil {
		t.Fatalf("ReadBranchRecords: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("fresh segment records = %d, want 0", len(recs))
	}
}

func TestBranchReadsWrittenRecords(t *testing.T) {
	ch, err := coverage.NewChannel(makeFakeLib(t))
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()

	want := []wantRecord{
		{siteID: 0, predicate: 6, bitWidth: 32, lhs: 0xFFFFFFFFFFFFFFFF, rhs: 0xFFFFFFFFFFFFFC18},
		{siteID: 1, predicate: 2, bitWidth: 32, lhs: 7, rhs: 1000},
		{siteID: 2, predicate: 4, bitWidth: 64, lhs: 0xDEADBEEFCAFEBABE, rhs: 0xDEADBEEFCAFEBABE},
	}
	writeBranchSegment(t, ch.BranchFD(), uint32(len(want)), 8, false, want)

	count, overflow, err := ch.ReadBranchSummary()
	if err != nil {
		t.Fatalf("ReadBranchSummary: %v", err)
	}
	if count != uint32(len(want)) || overflow {
		t.Errorf("summary = (%d, %v), want (%d, false)", count, overflow, len(want))
	}

	recs, err := ch.ReadBranchRecords()
	if err != nil {
		t.Fatalf("ReadBranchRecords: %v", err)
	}
	if len(recs) != len(want) {
		t.Fatalf("records = %d, want %d", len(recs), len(want))
	}
	for i, w := range want {
		got := recs[i]
		if got.SiteID != w.siteID || got.Predicate != w.predicate ||
			got.BitWidth != w.bitWidth || got.LHS != w.lhs || got.RHS != w.rhs {
			t.Errorf("record %d = %+v, want %+v", i, got, w)
		}
	}
}

func TestBranchOverflowFlag(t *testing.T) {
	ch, err := coverage.NewChannel(makeFakeLib(t))
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()

	writeBranchSegment(t, ch.BranchFD(), 2, 2, true, []wantRecord{
		{siteID: 10, predicate: 0, bitWidth: 8},
		{siteID: 11, predicate: 1, bitWidth: 16},
	})

	_, overflow, err := ch.ReadBranchSummary()
	if err != nil {
		t.Fatalf("ReadBranchSummary: %v", err)
	}
	if !overflow {
		t.Error("overflow = false, want true")
	}
}

// A corrupt count larger than capacity must not read past the records
// the segment can hold.
func TestBranchCountClampedToCapacity(t *testing.T) {
	ch, err := coverage.NewChannel(makeFakeLib(t))
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()

	writeBranchSegment(t, ch.BranchFD(), 100, 3, true, []wantRecord{
		{siteID: 0}, {siteID: 1}, {siteID: 2},
	})

	recs, err := ch.ReadBranchRecords()
	if err != nil {
		t.Fatalf("ReadBranchRecords: %v", err)
	}
	if len(recs) != 3 {
		t.Errorf("clamped records = %d, want 3", len(recs))
	}
}

func TestResetBranchZeroes(t *testing.T) {
	ch, err := coverage.NewChannel(makeFakeLib(t))
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()

	writeBranchSegment(t, ch.BranchFD(), 1, 4, true, []wantRecord{{siteID: 9}})
	if err := ch.ResetBranch(); err != nil {
		t.Fatalf("ResetBranch: %v", err)
	}
	count, overflow, err := ch.ReadBranchSummary()
	if err != nil {
		t.Fatalf("ReadBranchSummary: %v", err)
	}
	if count != 0 || overflow {
		t.Errorf("after reset summary = (%d, %v), want (0, false)", count, overflow)
	}
}

func TestBranchClosedChannelErrors(t *testing.T) {
	ch, err := coverage.NewChannel(makeFakeLib(t))
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	if err := ch.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := ch.ResetBranch(); err == nil {
		t.Error("ResetBranch on closed channel returned nil error")
	}
	if _, _, err := ch.ReadBranchSummary(); err == nil {
		t.Error("ReadBranchSummary on closed channel returned nil error")
	}
	if _, err := ch.ReadBranchRecords(); err == nil {
		t.Error("ReadBranchRecords on closed channel returned nil error")
	}
}
