# security-guard: ignore-file
"""Tests for the canonical scoring model (``core.scoring``).

These tests pin the contract that the dashboard, CLI and PDF report all rely
on. Changing a penalty or grade threshold should require updating both the
constant and the corresponding test — that's intentional friction.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scoring import (
    PENALTIES,
    GRADE_THRESHOLDS,
    penalty_for,
    calculate_score,
    get_grade,
    score_and_grade,
)
from scanners.base import Severity


class TestPenalties(unittest.TestCase):
    def test_all_severities_present(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertIn(sev, PENALTIES)

    def test_penalties_are_monotonic(self):
        # CRITICAL must hurt more than HIGH, HIGH more than MEDIUM, etc.
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        values = [PENALTIES[s] for s in order]
        for a, b in zip(values, values[1:]):
            self.assertGreater(a, b, f"penalties not monotonic: {values}")

    def test_penalty_for_accepts_string_and_enum(self):
        self.assertEqual(penalty_for("HIGH"), penalty_for(Severity.HIGH))
        self.assertEqual(penalty_for("critical"), penalty_for("CRITICAL"))

    def test_penalty_for_unknown_falls_back_to_info(self):
        self.assertEqual(penalty_for("BANANA"), PENALTIES["INFO"])


class TestCalculateScore(unittest.TestCase):
    def test_empty_returns_perfect_score(self):
        self.assertEqual(calculate_score([]), 100.0)

    def test_single_critical(self):
        self.assertEqual(calculate_score([{"severity": "CRITICAL"}]), 85.0)

    def test_mixed_findings(self):
        # 1 CRIT (-15) + 2 MED (-8) + 3 LOW (-6) = -29 → 71
        findings = (
            [{"severity": "CRITICAL"}]
            + [{"severity": "MEDIUM"}] * 2
            + [{"severity": "LOW"}] * 3
        )
        self.assertEqual(calculate_score(findings), 71.0)

    def test_score_never_negative(self):
        # 100 CRITs would be -1500; result must clamp at 0.
        findings = [{"severity": "CRITICAL"}] * 100
        self.assertEqual(calculate_score(findings), 0.0)

    def test_accepts_finding_objects(self):
        # Must work with both dicts (web JSON) and Finding objects (CLI).
        from scanners.base import Finding, Category
        f = Finding(
            title="x", severity=Severity.HIGH, category=Category.INJECTION,
            file_path="a", line_number=1, code_snippet="", description="",
            recommendation="",
        )
        self.assertEqual(calculate_score([f]), 92.0)


class TestGetGrade(unittest.TestCase):
    def test_boundaries(self):
        # Inclusive lower bounds per the GRADE_THRESHOLDS table.
        self.assertEqual(get_grade(100), "A")
        self.assertEqual(get_grade(90),  "A")
        self.assertEqual(get_grade(89.9), "B")
        self.assertEqual(get_grade(80),  "B")
        self.assertEqual(get_grade(79.9), "C")
        self.assertEqual(get_grade(70),  "C")
        self.assertEqual(get_grade(60),  "D")
        self.assertEqual(get_grade(59.9), "F")
        self.assertEqual(get_grade(0),   "F")

    def test_thresholds_are_descending(self):
        # First-match-wins requires strictly descending thresholds.
        thresholds = [t for t, _ in GRADE_THRESHOLDS]
        self.assertEqual(thresholds, sorted(thresholds, reverse=True))


class TestScoreAndGrade(unittest.TestCase):
    def test_returns_pair(self):
        score, grade = score_and_grade([{"severity": "HIGH"}])
        self.assertEqual(score, 92.0)
        self.assertEqual(grade, "A")


if __name__ == "__main__":
    unittest.main()
