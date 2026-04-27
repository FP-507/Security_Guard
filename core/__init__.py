"""Core utilities for Security Guard.

This package contains the non-scanner logic:
  - scoring          — Single source of truth for the security score model
  - github_fetcher   — GitHub repo cloning (with private-repo detection)
  - pdf_generator    — Bilingual PDF report generation
  - report_generator — Console / HTML report generation (CLI mode)
"""

from . import github_fetcher
from .pdf_generator import generate_pdf
from .scoring import calculate_score, get_grade, score_and_grade, PENALTIES
from .report_generator import (
    print_console_report,
    generate_html_report,
    calculate_security_score,  # backwards-compat alias for calculate_score
)

__all__ = [
    "github_fetcher",
    "generate_pdf",
    "print_console_report",
    "generate_html_report",
    # Scoring (canonical):
    "calculate_score",
    "get_grade",
    "score_and_grade",
    "PENALTIES",
    # Back-compat:
    "calculate_security_score",
]
