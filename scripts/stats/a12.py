"""Dependency-free Vargha-Delaney A12 effect size.

ADR 0032: the reproducible dev image (ADR 0006) ships only the python3
standard library — no numpy, no scipy — so the benchmark harness carries
its own statistics. This module is the canonical home of the effect size
that ``docs/EVALUATION.md`` §6 requires next to every p-value; the
Mann-Whitney p itself lives in ``mannwhitney.py`` beside this file.

A12(X, Y) = P(X > Y) + 0.5 * P(X = Y) — the probability that a value drawn
at random from X beats a value drawn at random from Y, with ties split in
half. It is computed as an exact ``Fraction`` over the len(X) * len(Y)
pairs, so 1/3 stays 1/3 and the printed three decimals are a rounding of
the true value rather than of a float that already drifted.

The wording of the magnitude label and the thresholds 0.56 / 0.64 / 0.71
(applied symmetrically to |A12 - 0.5|) are carried over verbatim from the
experiment that first published these numbers,
``docs/experiments/comparative-effect-size/report.md``; that file and its
own copy of the arithmetic stay where they are, untouched — this module is
a port, not a move.

Pure standard library: only ``fractions``.
"""

from __future__ import annotations

from fractions import Fraction

# Пороги величины эффекта по |A12 - 0.5|: 0.56 / 0.64 / 0.71 симметрично.
T_SMALL = Fraction(6, 100)
T_MEDIUM = Fraction(14, 100)
T_LARGE = Fraction(21, 100)


def a12(xs, ys):
    """A12(X, Y) = P(X > Y) + 0.5 * P(X = Y) как точная дробь.

    Связки засчитываются половиной — это и есть содержательное отличие A12
    от «доли выигранных пар»: при полном совпадении выборок получается
    ровно 0.5, а не 0.0 и не 1.0.

    Возвращает ``Fraction``. Поднимает ``ValueError`` на пустой выборке:
    величина там не определена, и молчаливый 0.5 был бы враньём.
    """
    if not xs or not ys:
        raise ValueError("A12 не определён на пустой выборке")
    greater = 0
    ties = 0
    for x in xs:
        for y in ys:
            if x > y:
                greater += 1
            elif x == y:
                ties += 1
    return Fraction(2 * greater + ties, 2 * len(xs) * len(ys))


def magnitude(value):
    """Словесная величина эффекта по выписанным в шапке порогам."""
    d = abs(Fraction(value) - Fraction(1, 2))
    if d >= T_LARGE:
        return "большой"
    if d >= T_MEDIUM:
        return "средний"
    if d >= T_SMALL:
        return "малый"
    return "пренебрежимый"


def fmt3(frac):
    """Три знака после точки без плавающей арифметики, половина — вверх."""
    frac = Fraction(frac)
    neg = frac < 0
    scaled = int(abs(frac) * 1000 + Fraction(1, 2))
    return "%s%d.%03d" % ("-" if neg else "", scaled // 1000, scaled % 1000)


def _parse_sample(text):
    """Выборка из строки «1,2,3» — для CLI; пустая строка не выборка."""
    items = [p.strip() for p in text.split(",") if p.strip() != ""]
    if not items:
        raise ValueError("пустая выборка: %r" % (text,))
    return [Fraction(p) for p in items]


def main(argv):
    if len(argv) != 2:
        raise SystemExit(
            "использование: python3 scripts/stats/a12.py <X через запятую> <Y через запятую>"
        )
    xs = _parse_sample(argv[0])
    ys = _parse_sample(argv[1])
    value = a12(xs, ys)
    print(
        "A12=%s magnitude=%s n_x=%d n_y=%d exact=%s"
        % (fmt3(value), magnitude(value), len(xs), len(ys), value)
    )
    return 0


if __name__ == "__main__":
    import sys

    try:
        raise SystemExit(main(sys.argv[1:]))
    except ValueError as exc:
        raise SystemExit("a12: %s" % exc)
