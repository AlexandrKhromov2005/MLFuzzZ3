// Micro-target under test: gate over the SUM of two verbatim input fields.
//   a = u32 LE at offset 0, b = u32 LE at offset 4, both present verbatim.
//   The sum a+b is NOT present in the input.
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
    if (a + b == MAGIC) {
      abort();
    }
  }
  return 0;
}
