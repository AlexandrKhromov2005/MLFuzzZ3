// Micro-target under test: gate over the XOR of two verbatim input fields --
// the boundary cell of the solver domain map (task-034, ADR 0035).
//   a = u32 LE at offset 0, b = u32 LE at offset 4, both present verbatim.
//   The value a^b is NOT present in the input.
// The map calls xor NO-BINDING except as an alias of the sum when the operand
// bits do not overlap (docs/experiments/solver-domain-map/report.md:138); this
// fixture is what lets that caveat be checked on a real target.
// See gate_guard.h for why the gate is nested inside guard(a, b).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gate_guard.h"

#define MAGIC 0xDEADBEEFu

int main(void) {
  uint8_t buf[64];
  size_t n = fread(buf, 1, sizeof(buf), stdin);
  if (n < 8) return 0;

  uint32_t a, b;
  memcpy(&a, buf + 0, 4);
  memcpy(&b, buf + 4, 4);

  if (guard(a, b)) {
    if ((a ^ b) == MAGIC) {
      abort();
    }
  }
  return 0;
}
