package coverage

import "encoding/binary"

// Branch-value channel ABI (ADR 0033). Mirrors the runtime layout in
// src/runtime/coverage/mlfuzzz3_branch.h — the single source of truth.
// Go cannot include the C header, so these constants are kept in sync
// by hand (and asserted by branch_test.go against the fixed offsets).
//
// Segment: a 16-byte header followed by capacity 24-byte records.
//
//   header : count u32 @0 | capacity u32 @4 | overflow u32 @8 | _ @12
//   record : site_id u32 @0 | predicate u8 @4 | bit_width u8 @5 |
//            _ u16 @6 | lhs u64 @8 | rhs u64 @16
//
// All little-endian (the only platform the runtime targets).

// BranchSegmentSize is the byte size of each branch-value SHM segment.
// The runtime derives the record capacity from this physical size via
// fstat (it does not grow the segment), so sizing is owned here. 1 MiB
// holds ~43k records of 24 bytes; on overflow the runtime sets a flag
// and drops further records (ADR 0033 overflow contract).
const BranchSegmentSize = 1 << 20

const (
	branchHeaderSize = 16
	branchRecordSize = 24

	branchOffCount    = 0
	branchOffCapacity = 4
	branchOffOverflow = 8

	recOffSiteID    = 0
	recOffPredicate = 4
	recOffBitWidth  = 5
	recOffLHS       = 8
	recOffRHS       = 16
)

// branchSchemaVersion is the BranchValuesDescriptor.schema_version
// field. Bumped on any incompatible branch-segment layout change.
const branchSchemaVersion uint32 = 1

// branchShmName is the cosmetic memfd label advertised in the
// descriptor (visible in /proc/<pid>/fd/<n>). Not a registry key.
const branchShmName = "branch-values"

// BranchRecord is one logged comparison, decoded from the segment.
// Predicate values follow enum fuzzer_rt_cmp_kind in the runtime ABI.
type BranchRecord struct {
	SiteID    uint32
	Predicate uint8
	BitWidth  uint8
	LHS       uint64
	RHS       uint64
}

// parseBranchHeader reads count and the overflow flag from a segment.
// buf must be at least branchHeaderSize bytes.
func parseBranchHeader(buf []byte) (count uint32, overflow bool) {
	count = binary.LittleEndian.Uint32(buf[branchOffCount:])
	overflow = binary.LittleEndian.Uint32(buf[branchOffOverflow:]) != 0
	return count, overflow
}

// parseBranchRecords decodes the records following the header. The
// number decoded is the header count, clamped to both the segment
// capacity and the physical buffer so a corrupt count can never read
// out of bounds.
func parseBranchRecords(buf []byte) []BranchRecord {
	count := binary.LittleEndian.Uint32(buf[branchOffCount:])
	capacity := binary.LittleEndian.Uint32(buf[branchOffCapacity:])
	if count > capacity {
		count = capacity
	}
	maxByBuf := uint32((len(buf) - branchHeaderSize) / branchRecordSize)
	if count > maxByBuf {
		count = maxByBuf
	}
	recs := make([]BranchRecord, count)
	for i := uint32(0); i < count; i++ {
		off := branchHeaderSize + int(i)*branchRecordSize
		rec := buf[off : off+branchRecordSize]
		recs[i] = BranchRecord{
			SiteID:    binary.LittleEndian.Uint32(rec[recOffSiteID:]),
			Predicate: rec[recOffPredicate],
			BitWidth:  rec[recOffBitWidth],
			LHS:       binary.LittleEndian.Uint64(rec[recOffLHS:]),
			RHS:       binary.LittleEndian.Uint64(rec[recOffRHS:]),
		}
	}
	return recs
}
