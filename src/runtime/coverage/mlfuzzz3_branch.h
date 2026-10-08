// mlfuzzz3 branch-value channel ABI (ADR 0033).
//
// Single source of truth for the on-wire layout of the
// branch-value SHM segment. Shared between:
//   - the runtime writer  (mlfuzzz3_cov.c),
//   - the C++ core reader  (src/core, ADR 0033 Шаг 6), and
//   - conceptually the Go exec-server, which mirrors these
//     sizes/values in Go (it cannot include this C header).
//
// The branch channel is a SEPARATE SHM segment from the
// 64 KiB edge bitmap (ADR 0033 Развилка 3). The runtime
// appends one fixed-size record per executed user-level
// icmp, up to a fixed capacity. On overflow it sets a flag
// and drops the record WITHOUT growing the segment.
//
// Segment layout (little-endian — the only platform this
// targets; offsets pinned by static_assert below so any
// accidental drift breaks the build, not a run):
//
//   offset 0  : fuzzer_rt_branch_header   (16 bytes)
//   offset 16 : fuzzer_rt_branch_record[capacity]
//
// capacity is derived from the physical segment size by the
// writer at startup; the orchestrator owns segment sizing.

#pragma once

#include <stddef.h>  // offsetof
#include <stdint.h>

#ifndef __cplusplus
#include <assert.h>  // C11: static_assert -> _Static_assert
#endif

// Comparison predicate kind. The VALUES are part of the ABI:
// the branch-tracing LLVM pass (src/instrumentation) emits
// these integers, the core reader interprets them. Signed and
// unsigned variants are DISTINCT (ADR 0033 Развилка 1) — they
// map to different Z3 BV predicates in the later concolic
// stage (0034+). Values are fixed; do not renumber or reorder.
enum fuzzer_rt_cmp_kind {
    kFuzzerRtCmpEq = 0,   // ==
    kFuzzerRtCmpNe = 1,   // !=
    kFuzzerRtCmpUlt = 2,  // unsigned  <
    kFuzzerRtCmpUle = 3,  // unsigned  <=
    kFuzzerRtCmpUgt = 4,  // unsigned  >
    kFuzzerRtCmpUge = 5,  // unsigned  >=
    kFuzzerRtCmpSlt = 6,  // signed    <
    kFuzzerRtCmpSle = 7,  // signed    <=
    kFuzzerRtCmpSgt = 8,  // signed    >
    kFuzzerRtCmpSge = 9,  // signed    >=
};

// Segment header. count/overflow_flag are written by the
// runtime as records arrive; capacity is set once at startup
// from the physical segment size. reserved pads the header to
// 16 bytes so the record array that follows is 8-byte aligned.
struct fuzzer_rt_branch_header {
    uint32_t count;          // records written so far
    uint32_t capacity;       // max records the segment holds
    uint32_t overflow_flag;  // 1 once any record was dropped
    uint32_t reserved;       // explicit pad -> header is 16 B
};

// One logged comparison. Fields are reordered relative to the
// logical (site_id, lhs, rhs, predicate, bit_width) tuple so
// the 16-bit hole after the two byte fields is filled
// explicitly: this yields a packed, natural-aligned 24-byte
// record (lhs/rhs land on 8-byte boundaries) with no implicit
// padding. site_id is deterministic module-order (ADR 0033).
struct fuzzer_rt_branch_record {
    uint32_t site_id;   // offset 0
    uint8_t predicate;  // offset 4  (enum fuzzer_rt_cmp_kind)
    uint8_t bit_width;  // offset 5  (operand width in bits)
    uint16_t reserved;  // offset 6  (explicit pad, zeroed)
    uint64_t lhs;       // offset 8
    uint64_t rhs;       // offset 16
};

static_assert(sizeof(struct fuzzer_rt_branch_header) == 16, "branch header layout drift");
static_assert(sizeof(struct fuzzer_rt_branch_record) == 24, "branch record layout drift");
static_assert(offsetof(struct fuzzer_rt_branch_record, lhs) == 8, "branch record lhs offset drift");
static_assert(offsetof(struct fuzzer_rt_branch_record, rhs) == 16,
              "branch record rhs offset drift");
