// Shared guard for the recon micro-targets (ADR-0047 §Открытый вопрос).
//
// The gate under test is nested inside guard(a, b). Its whole job is to exclude
// "solutions" in which the addition is not actually composing two fields:
//   - band [LO, HI]: neither operand may be near 0 or near 2^32, so no
//     wrap-around and no "b = -small" family;
//   - all four bytes non-zero: no byte-aligned decomposition of a dictionary
//     token (e.g. a=0x0000beef/b=0xdead0000, or b=0x7d000000 touching only the
//     top byte) — every solution needs carries across byte boundaries.
// All observed degenerate solutions from the pilot runs fall outside the guard;
// inside it, a solution requires genuine cross-field arithmetic.
#ifndef GATE_GUARD_H
#define GATE_GUARD_H

#include <stdint.h>

#define LO 0x01000000u
#define HI 0x7F000000u

static inline int nz32(uint32_t v) {
    return (v & 0xffu) && ((v >> 8) & 0xffu) && ((v >> 16) & 0xffu) && ((v >> 24) & 0xffu);
}

static inline int guard(uint32_t a, uint32_t b) {
    return a >= LO && a <= HI && b >= LO && b <= HI && nz32(a) && nz32(b);
}

#endif  // GATE_GUARD_H
