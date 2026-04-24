"""Core utilities for Security Guard.

This package contains the non-scanner logic:
  - github_fetcher   — GitHub repo cloning
  - pdf_generator    — Bilingual PDF report generation
  - report_generator — Console / HTML report generation (CLI mode)
"""

from . import github_fetcher
from .pdf_generator import generate_pdf
from .report_generator import (
    print_console_report,
    generate_html_report,
    calculate_security_score,
    get_grade,
)

__all__ = [
    "github_fetcher",
    "generate_pdf",
    "print_console_report",
    "generate_html_report",
    "calculate_security_score",
    "get_grade",
]
