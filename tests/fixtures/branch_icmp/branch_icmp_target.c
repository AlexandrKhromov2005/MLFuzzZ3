// Branch-channel fixture (ADR 0033 Шаг 3 / Шаг 6).
//
// Reads a fixed 32-byte window from stdin (zero-padded on short
// input) and performs five integer comparisons of known signedness
// and width against fixed magic constants. Because operands are read
// from fixed offsets, a KNOWN input yields KNOWN icmp operands — the
// branch-pass IR test (Шаг 3) checks the inserted instrumentation and
// the format smoke e2e (Шаг 6) checks the logged operand values.
//
// All five comparisons are on the straight-line path (independent
// `if` statements, no short-circuit), so every run executes exactly
// five icmps in source order. site_id is assigned 0..4 in that order
// by the branch-tracing pass.
//
//   site 0: int32  < -1000          -> SLT, width 32 (signed/sext)
//   site 1: uint32 < 1000u          -> ULT, width 32 (unsigned/zext)
//   site 2: uint32 == 0xCAFEBABEu   -> EQ,  width 32 (zext)
//   site 3: uint64 > MAGIC64        -> UGT, width 64 (unsigned/zext)
//   site 4: int64  > -100000        -> SGT, width 64 (signed/sext)
//
// The helpers assemble little-endian values without loops, so the
// translation unit contains no icmps other than the five above.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { kBufSize = 32 };

static const uint64_t kMagic64 = 0xDEADBEEFCAFEBABEULL;

static uint32_t load_u32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t load_u64_le(const uint8_t* p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

int main(void) {
    uint8_t buf[kBufSize];
    memset(buf, 0, sizeof(buf));
    (void)fread(buf, 1, sizeof(buf), stdin);  // short read -> zero pad

    int acc = 0;

    int32_t s32 = (int32_t)load_u32_le(&buf[0]);
    if (s32 < -1000) {  // site 0: SLT i32
        acc += 1;
    }

    uint32_t u32 = load_u32_le(&buf[4]);
    if (u32 < 1000u) {  // site 1: ULT i32
        acc += 2;
    }

    uint32_t e32 = load_u32_le(&buf[8]);
    if (e32 == 0xCAFEBABEu) {  // site 2: EQ i32
        acc += 4;
    }

    uint64_t u64 = load_u64_le(&buf[12]);
    if (u64 > kMagic64) {  // site 3: UGT i64
        acc += 8;
    }

    int64_t s64 = (int64_t)load_u64_le(&buf[20]);
    if (s64 > -100000) {  // site 4: SGT i64
        acc += 16;
    }

    return acc & 0x7f;
}
