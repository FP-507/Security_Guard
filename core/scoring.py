"""Single source of truth for the security score model.

The same penalty table and grade thresholds are used by:
  - the Flask web API (``app.py``) when computing JSON results
  - the CLI / HTML report (``core/report_generator.py``)
  - the PDF report (``core/pdf_generator.py``)

If these values ever drift apart again, the dashboard, the CLI and the PDF
will report different scores for the same findings. **Always import from
here.** Do not redefine penalties or thresholds anywhere else.

Public surface
--------------
- :data:`PENALTIES`        — points deducted per severity level
- :data:`GRADE_THRESHOLDS` — minimum score required for each letter grade
- :func:`penalty_for`      — points for one severity (accepts string or :class:`Severity`)
- :func:`calculate_score`  — score (0–100) from an iterable of findings or dicts
- :func:`get_grade`        — letter grade (A–F) from a numeric score
- :func:`score_and_grade`  — convenience returning both at once
"""

from typing import Iterable, Union

from scanners.base import Finding, Severity


# Points deducted per finding, by severity. ``INFO`` is intentionally non-zero
# so that "info-only" reports still differentiate noisy projects from clean
# ones, but small enough that a flood of INFO findings cannot swamp HIGH/CRIT.
PENALTIES: dict[str, float] = {
    "CRITICAL": 15.0,
    "HIGH":     8.0,
    "MEDIUM":   4.0,
    "LOW":      2.0,
    "INFO":     0.5,
}

# Minimum score (inclusive) required to receive each letter grade. Ordered
# from highest to lowest; the first match wins.
GRADE_THRESHOLDS: list[tuple[float, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0,  "F"),
]


def _severity_key(sev: Union[str, Severity]) -> str:
    """Normalize a Severity enum or its string value to the table key."""
    if isinstance(sev, Severity):
        return sev.value
    return str(sev).upper()


def penalty_for(severity: Union[str, Severity]) -> float:
    """Points deducted for a single finding of the given severity.

    Unknown / non-standard severities receive the ``INFO`` penalty so a
    typo in a scanner cannot accidentally inflate (or zero-out) a score.
    """
    return PENALTIES.get(_severity_key(severity), PENALTIES["INFO"])


def calculate_score(findings: Iterable[Union[Finding, dict]]) -> float:
    """Return a 0–100 security score for an iterable of findings.

    Accepts both :class:`Finding` instances (CLI / scanner output) and plain
    ``dict`` records (web JSON output) — they share the ``severity`` field.
    A clean project (no findings) gets the perfect score of 100.0.
    """
    penalty = 0.0
    for f in findings:
        sev = f.severity if isinstance(f, Finding) else f.get("severity")
        penalty += penalty_for(sev)
    return round(max(0.0, 100.0 - penalty), 1)


def get_grade(score: float) -> str:
    """Letter grade (A–F) for a numeric score."""
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"  # unreachable — the (0, "F") entry guarantees a match


def score_and_grade(findings: Iterable[Union[Finding, dict]]) -> tuple[float, str]:
    """Convenience: return ``(score, grade)`` in one call."""
    score = calculate_score(findings)
    return score, get_grade(score)
