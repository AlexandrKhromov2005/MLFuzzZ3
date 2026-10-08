"""Unit tests for the dependency-free Vargha-Delaney A12 effect-size module.

Run (not a CI gate; research tooling, ADR 0032):

    python3 scripts/stats/test_a12.py

Every expected value below is a KNOWN ANSWER worked out on paper from the
definition A12(X, Y) = P(X > Y) + 0.5 * P(X = Y), by enumerating the
len(X) * len(Y) pairs and counting strict wins and ties. None of them was
read off the behaviour of ``a12.py``: the file was written before the
module existed. Each case carries the pair count in a comment so the
arithmetic can be re-checked by hand.

The magnitude thresholds (0.56 / 0.64 / 0.71 applied symmetrically to
|A12 - 0.5|, i.e. 0.06 / 0.14 / 0.21) come from the published experiment
``docs/experiments/comparative-effect-size/report.md``; the boundary
values are tested explicitly because "greater or equal" versus "strictly
greater" is a convention, not a theorem.
"""

import os
import subprocess
import sys
import unittest
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import a12 as a12mod  # noqa: E402


# (name, X, Y, expected exact value, pairs, hand-worked reasoning)
KNOWN_ANSWERS = [
    (
        "identical samples",
        [1, 2, 3],
        [1, 2, 3],
        Fraction(1, 2),
        9,
        "3 ties + 3 strict wins + 3 strict losses -> (2*3 + 3) / (2*9) = 1/2",
    ),
    (
        "full domination",
        [10, 11, 12],
        [1, 2, 3],
        Fraction(1),
        9,
        "all 9 pairs won strictly, no ties -> (2*9 + 0) / (2*9) = 1",
    ),
    (
        "full lag",
        [1, 2, 3],
        [10, 11, 12],
        Fraction(0),
        9,
        "no pair won, no ties -> 0 / (2*9) = 0",
    ),
    (
        "every pair a tie",
        [5, 5, 5],
        [5, 5, 5],
        Fraction(1, 2),
        9,
        "all 9 pairs are ties, each counted as a half: 4.5 / 9 = 1/2",
    ),
    (
        "ties mixed in",
        [1, 2],
        [1, 3],
        Fraction(3, 8),
        4,
        "(1,1) tie, (1,3) loss, (2,1) win, (2,3) loss -> (2*1 + 1) / (2*4) = 3/8",
    ),
    (
        "unequal lengths, tie on the boundary",
        [1, 2, 3, 4],
        [2],
        Fraction(5, 8),
        4,
        "(1,2) loss, (2,2) tie, (3,2) win, (4,2) win -> (2*2 + 1) / (2*4) = 5/8",
    ),
    (
        "unequal lengths with repeated ties",
        [1, 1, 2],
        [1, 3],
        Fraction(1, 3),
        6,
        "(1,1)T (1,3)L (1,1)T (1,3)L (2,1)W (2,3)L -> (2*1 + 2) / (2*6) = 1/3",
    ),
    (
        "both samples of length one, win",
        [5],
        [3],
        Fraction(1),
        1,
        "the single pair is a strict win -> (2*1 + 0) / (2*1) = 1",
    ),
    (
        "both samples of length one, tie",
        [5],
        [5],
        Fraction(1, 2),
        1,
        "the single pair is a tie -> (2*0 + 1) / (2*1) = 1/2",
    ),
    (
        "both samples of length one, loss",
        [5],
        [7],
        Fraction(0),
        1,
        "the single pair is a strict loss -> 0 / (2*1) = 0",
    ),
    (
        "sample of length one against three",
        [2],
        [1, 2, 3],
        Fraction(1, 2),
        3,
        "(2,1) win, (2,2) tie, (2,3) loss -> (2*1 + 1) / (2*3) = 1/2",
    ),
]


class A12KnownAnswerTest(unittest.TestCase):
    def test_known_answers(self):
        for name, xs, ys, expected, pairs, why in KNOWN_ANSWERS:
            with self.subTest(case=name):
                self.assertEqual(len(xs) * len(ys), pairs, why)
                self.assertEqual(a12mod.a12(xs, ys), expected, why)

    def test_result_is_exact_fraction(self):
        # Not a float: 3/8 is representable, 1/3 is not, and the module must
        # not lose it. This is what lets the printed value be trusted.
        self.assertIsInstance(a12mod.a12([1, 2], [1, 3]), Fraction)
        self.assertEqual(a12mod.a12([1, 1, 2], [1, 3]), Fraction(1, 3))

    def test_antisymmetry(self):
        # A12(X, Y) + A12(Y, X) = 1 for any non-empty samples.
        for xs, ys in ([7, 1, 9, 9], [9, 2, 2]), ([1, 2], [1, 3]), ([5], [5]):
            with self.subTest(xs=xs, ys=ys):
                self.assertEqual(a12mod.a12(xs, ys) + a12mod.a12(ys, xs), 1)

    def test_order_within_a_sample_does_not_matter(self):
        self.assertEqual(a12mod.a12([3, 1, 2], [2, 3, 1]), a12mod.a12([1, 2, 3], [1, 2, 3]))

    def test_floats_accepted(self):
        self.assertEqual(a12mod.a12([1.0, 2.0], [1.0, 3.0]), Fraction(3, 8))

    def test_empty_sample_raises(self):
        with self.assertRaises(ValueError):
            a12mod.a12([], [1, 2])
        with self.assertRaises(ValueError):
            a12mod.a12([1, 2], [])
        with self.assertRaises(ValueError):
            a12mod.a12([], [])


class MagnitudeTest(unittest.TestCase):
    def test_thresholds_are_the_published_ones(self):
        self.assertEqual(a12mod.T_SMALL, Fraction(6, 100))
        self.assertEqual(a12mod.T_MEDIUM, Fraction(14, 100))
        self.assertEqual(a12mod.T_LARGE, Fraction(21, 100))

    def test_labels_above_the_midpoint(self):
        self.assertEqual(a12mod.magnitude(Fraction(1, 2)), "пренебрежимый")
        self.assertEqual(a12mod.magnitude(Fraction(55, 100)), "пренебрежимый")
        self.assertEqual(a12mod.magnitude(Fraction(56, 100)), "малый")
        self.assertEqual(a12mod.magnitude(Fraction(63, 100)), "малый")
        self.assertEqual(a12mod.magnitude(Fraction(64, 100)), "средний")
        self.assertEqual(a12mod.magnitude(Fraction(70, 100)), "средний")
        self.assertEqual(a12mod.magnitude(Fraction(71, 100)), "большой")
        self.assertEqual(a12mod.magnitude(Fraction(1)), "большой")

    def test_labels_are_symmetric_below_the_midpoint(self):
        # |A12 - 0.5| is what the label reads, so 0.44 must label like 0.56.
        for above, below in ((55, 45), (56, 44), (64, 36), (71, 29)):
            with self.subTest(above=above, below=below):
                self.assertEqual(
                    a12mod.magnitude(Fraction(above, 100)),
                    a12mod.magnitude(Fraction(below, 100)),
                )
        self.assertEqual(a12mod.magnitude(Fraction(0)), "большой")


class Fmt3Test(unittest.TestCase):
    def test_three_decimals_without_floats(self):
        self.assertEqual(a12mod.fmt3(Fraction(3, 8)), "0.375")
        self.assertEqual(a12mod.fmt3(Fraction(1, 2)), "0.500")
        self.assertEqual(a12mod.fmt3(Fraction(0)), "0.000")
        self.assertEqual(a12mod.fmt3(Fraction(1)), "1.000")
        self.assertEqual(a12mod.fmt3(Fraction(1, 3)), "0.333")

    def test_half_rounds_up_not_to_even(self):
        # 0.0005 -> 0.001 and 0.0015 -> 0.002: banker's rounding would give
        # 0.000 and 0.002.
        self.assertEqual(a12mod.fmt3(Fraction(5, 10000)), "0.001")
        self.assertEqual(a12mod.fmt3(Fraction(15, 10000)), "0.002")


class CliTest(unittest.TestCase):
    def test_cli_prints_value_and_label(self):
        out = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "a12.py"),
             "1,2", "1,3"],
            capture_output=True, text=True, check=True,
        ).stdout
        self.assertIn("A12=0.375", out)
        self.assertIn("magnitude=малый", out)

    def test_cli_rejects_an_empty_sample(self):
        done = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "a12.py"),
             "", "1,3"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
