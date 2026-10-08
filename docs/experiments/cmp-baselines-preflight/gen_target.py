#!/usr/bin/env python3
"""Порождает цель для предполётного замера двух плеч сравнения (task-132).

Отличие от docs/experiments/instrumentation-cost/gen_target.py: там все
сравнения ОДНОБАЙТОВЫЕ (`d[i] < 137`), и на такой цели ни laf-intel, ни
трассировка сравнений показать себя не могут по построению — оба плеча
существуют ради проламывания МНОГОБАЙТОВЫХ констант. Поэтому цель здесь
своя: каждое сравнение — равенство загруженного 16/32/64-битного слова с
константой. Соседний генератор не изменён ни байтом и не переиспользован.

Детерминирован по зерну: никакого времени, окружения и чтения ФС.
"""

import argparse
import hashlib
import random

WIDTHS = (2, 4, 8)
CTYPE = {2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}
BUF = 128


def render(seed, funcs, cmps):
    rnd = random.Random(seed)
    out = []
    add = out.append
    add("/* Порождено gen_target.py, правка руками бессмысленна. */")
    add("#include <stdint.h>")
    add("#include <stdio.h>")
    add("#include <string.h>")
    add("")
    widths_used = {2: 0, 4: 0, 8: 0}
    for f in range(funcs):
        add("static uint32_t chk_%d(const uint8_t *d, size_t n) {" % f)
        add("  uint32_t h = %du;" % rnd.randrange(1, 1 << 31))
        add("  if (n < %d) return h;" % BUF)
        for _ in range(cmps):
            w = rnd.choice(WIDTHS)
            widths_used[w] += 1
            off = rnd.randrange(0, BUF - 8)
            konst = rnd.randrange(1 << (8 * w - 8), 1 << (8 * w))
            add("  {")
            add("    %s v;" % CTYPE[w])
            add("    memcpy(&v, d + %d, sizeof v);" % off)
            add("    if (v == %duLL) {" % konst)
            add("      h ^= %du;" % rnd.randrange(1, 1 << 20))
            add("    } else {")
            add("      h += %du;" % rnd.randrange(1, 1 << 20))
            add("    }")
            add("  }")
        add("  return h;")
        add("}")
        add("")
    add("uint32_t mlfuzzz3_cmp_target(const uint8_t *d, size_t n) {")
    add("  uint32_t acc = 0u;")
    for f in range(funcs):
        add("  acc ^= chk_%d(d, n);" % f)
    add("  return acc;")
    add("}")
    add("")
    add("int main(int argc, char **argv) {")
    add("  uint8_t buf[%d];" % BUF)
    add("  size_t n = 0;")
    add("  (void)argc;")
    add("  (void)argv;")
    add("  memset(buf, 0, sizeof(buf));")
    add("  n = fread(buf, 1, sizeof(buf), stdin);")
    add("  return (int)(mlfuzzz3_cmp_target(buf, n) & 0x7fu);")
    add("}")
    return "\n".join(out) + "\n", widths_used


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--funcs", type=int, default=80)
    ap.add_argument("--cmps", type=int, default=30)
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()

    text, widths = render(args.seed, args.funcs, args.cmps)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    md5 = hashlib.md5(text.encode()).hexdigest()
    print(
        "gen_target: seed=%d funcs=%d cmps_per_func=%d cmps_total=%d "
        "w16=%d w32=%d w64=%d bytes=%d md5=%s"
        % (
            args.seed,
            args.funcs,
            args.cmps,
            args.funcs * args.cmps,
            widths[2],
            widths[4],
            widths[8],
            len(text.encode()),
            md5,
        )
    )


if __name__ == "__main__":
    main()
