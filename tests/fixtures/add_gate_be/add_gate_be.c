// Micro-target under test: gate over the SUM of two verbatim input fields.
//   a = u32 BE at offset 0, b = u32 BE at offset 4, both present verbatim.
//   The sum a+b is NOT present in the input.
// See gate_guard.h for why the gate is nested inside guard(a, b).
//
// Byte-order variant of tests/fixtures/add_gate/add_gate.c (task-080). The
// ONLY difference from the donor is how the two fields are decoded: the donor
// takes them in the host (little-endian) order via memcpy, this one takes them
// big-endian via load_be32(). Offsets (0 and 4), field width (4 bytes), the
// gate form (a + b == MAGIC), MAGIC itself, the buffer size, the short-input
// cut-off and gate_guard.h are the donor's, unchanged. load_be32() contains no
// comparison, so it adds no instrumented branch to the trace the solver reads.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gate_guard.h"

#define MAGIC 0xDEADBEEFu

static inline uint32_t load_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         ((uint32_t)p[3]);
}

int main(void) {
  uint8_t buf[64];
  size_t n = fread(buf, 1, sizeof(buf), stdin);
  if (n < 8) return 0;

  uint32_t a, b;
  a = load_be32(buf + 0);
  b = load_be32(buf + 4);

  if (guard(a, b)) {
    if (a + b == MAGIC) {
      abort();
    }
  }
  return 0;
}
