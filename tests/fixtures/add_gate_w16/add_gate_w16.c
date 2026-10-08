// Micro-target under test: gate over the SUM of two verbatim input fields.
//   a = u16 LE at offset 0, b = u16 LE at offset 2, both present verbatim.
//   The sum a+b is NOT present in the input.
//
// Field-WIDTH variant of tests/fixtures/add_gate/add_gate.c (task-102,
// ADR-0047). The donor takes two u32 fields at offsets 0 and 4; this one takes
// two u16 fields at offsets 0 and 2, in the same host (little-endian) order and
// through the same memcpy. The gate form (a + b == MAGIC nested inside a
// guard), the 64-byte buffer and the abort() are the donor's, unchanged.
//
// Exactly three things scale with the width, and nothing else:
//
//   * MAGIC 0xDEADBEEF -> 0xBEEF, its low half. A 32-bit magic is unreachable
//     from a pair of 16-bit fields, so keeping it would make the gate dead
//     code rather than a harder gate.
//
//   * The guard band [0x01000000, 0x7F000000] -> [0x0100, 0x7F00] and the
//     four-nonzero-bytes test -> two nonzero bytes. This is why the donor's
//     gate_guard.h is NOT included here, unlike tests/fixtures/add_gate_be/
//     which shares it with -I: the donor's LO alone already exceeds the whole
//     u16 range, so including it would reject every input and the crash would
//     be unreachable. The guard's PURPOSE is the donor's (gate_guard.h:1-11),
//     unchanged: no wrap-around, no operand near zero, and no byte-aligned
//     decomposition of the magic, so every solution still needs a carry across
//     the byte boundary and no degenerate "solution" counts.
//
//   * The short-input cut-off 8 -> 4 bytes, the number of bytes the two fields
//     actually occupy. The arm seed the harness feeds is still 8 bytes
//     (test_add_gate_w16_crash_budget.cpp:kArmSeed): the task varies the width
//     of the TARGET's fields, not the input the arm starts from, so bytes 4..7
//     are present and unused, as they would be in any real format.
//
// The sum is computed in 32 bits (both operands zero-extended), so it does not
// wrap: under the guard a + b <= 0xFE00 and MAGIC < 0xFE00 -- the same relation
// the donor has at 32 bits, where a + b <= 0xFE000000 and MAGIC < 0xFE000000.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC 0xBEEFu

#define LO16 0x0100u
#define HI16 0x7F00u

static inline int nz16(uint16_t v) {
    return (v & 0xffu) && ((v >> 8) & 0xffu);
}

static inline int guard(uint16_t a, uint16_t b) {
    return a >= LO16 && a <= HI16 && b >= LO16 && b <= HI16 && nz16(a) && nz16(b);
}

int main(void) {
  uint8_t buf[64];
  size_t n = fread(buf, 1, sizeof(buf), stdin);
  if (n < 4) return 0;

  uint16_t a, b;
  memcpy(&a, buf + 0, 2);
  memcpy(&b, buf + 2, 2);

  if (guard(a, b)) {
    if ((uint32_t)a + (uint32_t)b == MAGIC) {
      abort();
    }
  }
  return 0;
}
