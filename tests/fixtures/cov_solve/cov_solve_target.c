// Solver-necessary fixture (ADR 0034 prep — PROVISIONAL).
//
// Reads a uint32 (little-endian) from the first four input bytes into x
// and aborts only when x satisfies a SYSTEM of four integer constraints
// at once. The system is built so that reaching the crash needs a
// constraint solver, not input-to-state copying of a logged operand:
//
//   site 0: x >  0x10000000                       -> UGT i32
//   site 1: x <  0x20000000                       -> ULT i32
//   site 2: (x % 7) == 3                           -> EQ  i32 on a derived value
//   site 3: ((x ^ 0x5A5A5A5A) & 0xFFFF) > 0x4000   -> UGT i32 on a derived value
//
// No comparison operand equals a satisfying x, so copying any single
// logged operand into the input does not reach the crash; and two of the
// relations (modulo, xor-window) are non-range, so the conjunction has to
// be solved rather than brute-forced from the branch log. One satisfying
// value is x = 0x10000001 (see the smoke test): it is just inside the
// range, 0x10000001 % 7 == 3, and (0x0001 ^ 0x5A5A) = 0x5A5B > 0x4000.
//
// The constraints are nested `if`s, so each is a distinct icmp the
// branch-tracing pass instruments in source order (site_id 0..3); the
// helper assembles the little-endian word without loops, so the
// translation unit contains no other icmps.
//
// ADR 0034 (concolic) may refine these gates; this fixture is a
// provisional placeholder prepared ahead of that work.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { kBufSize = 4 };

static uint32_t load_u32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(void) {
    uint8_t buf[kBufSize];
    memset(buf, 0, sizeof(buf));
    (void)fread(buf, 1, sizeof(buf), stdin);  // short read -> zero pad

    uint32_t x = load_u32_le(&buf[0]);

    if (x > 0x10000000u) {                                      // site 0: UGT i32
        if (x < 0x20000000u) {                                  // site 1: ULT i32
            if ((x % 7u) == 3u) {                               // site 2: EQ i32 on (x % 7)
                if (((x ^ 0x5A5A5A5Au) & 0xFFFFu) > 0x4000u) {  // site 3: UGT i32
                    abort();
                }
            }
        }
    }
    return 0;
}
