// Cross-field Z3-necessary fixture (ADR 0035).
//
// Reads two uint32 (little-endian) fields x and y from the first eight
// input bytes (x = bytes 0..3, y = bytes 4..7) and aborts only when x and
// y jointly satisfy a system that LINKS the two fields:
//
//   site 0: x > 0x10000000          -> UGT i32
//   site 1: y > 0x10000000          -> UGT i32
//   site 2: x < y                   -> ULT i32 (cross-field: both operands are fields)
//   site 3: (uint32_t)(x + y) == 5  -> EQ  i32 (cross-field sum with defined wrap)
//
// Reaching the crash needs a constraint solver over BOTH fields at once:
// the ordering (site 2) and the wrapping sum (site 3) cannot be satisfied
// by copying any single logged operand into one field (input-to-state /
// RedQueen). Both fields lie in the input literally, so the concolic
// orchestrator (session B) can place the solved pair; the sum relation is
// reconstructed as a two-variable (kAddVars) constraint.
//
// One satisfying pair (found by hand, hard-coded in the smoke test):
//   x = 0x40000000, y = 0xC0000005
//   -> x,y > 0x10000000; x < y; x + y = 0x100000005, wrapped u32 = 5.
// No single observed operand reaches the crash: x = 0x10000000 or y = 5
// each break a lower bound or the sum, so the precise joint pair is
// required.
//
// Both fields are uint32_t (NOT int32_t): unsigned overflow is defined in
// C, so the runtime wrap matches the Z3 bvadd model (ADR 0035 SMT-encoding
// invariants). The comparisons are straight-line nested `if`s, so the
// branch-tracing pass logs each as a distinct icmp in source order
// (site_id 0..3); the helper assembles each little-endian word without
// loops, so the translation unit contains no other icmps.
//
// ADR 0035 fixture for cross-field Z3-necessity (supersedes the abandoned
// single-value 0034 approach).

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { kBufSize = 8 };

static uint32_t load_u32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(void) {
    uint8_t buf[kBufSize];
    memset(buf, 0, sizeof(buf));
    (void)fread(buf, 1, sizeof(buf), stdin);  // short read -> zero pad

    uint32_t x = load_u32_le(&buf[0]);
    uint32_t y = load_u32_le(&buf[4]);

    if (x > 0x10000000u) {                       // site 0: C1 UGT i32
        if (y > 0x10000000u) {                   // site 1: C2 UGT i32
            if (x < y) {                         // site 2: C3 ULT i32 (cross-field)
                if ((uint32_t)(x + y) == 5u) {   // site 3: C4 EQ i32 (wrap sum)
                    abort();
                }
            }
        }
    }
    return 0;
}
