#!/usr/bin/env python3
"""
Security Guard — Comprehensive Project Security Analyzer (CLI)
==============================================================

Analyzes a project directory for security vulnerabilities, simulates attacks,
and provides actionable remediation recommendations to reach 90% security.

The list of available scanners (and their short ids) comes from
``scanners.registry`` so the CLI never drifts from the web dashboard.

Usage:
    python security_guard.py <project_path> [options]

Options:
    --html           Generate HTML report (saved to reports/)
    --no-color       Disable colored output
    --scanners       Comma-separated list of scanner keys to run, or ``all``
                     (default: all code scanners — the ``web`` scanner is
                     skipped because it expects a URL, not a path)
    --severity       Minimum severity to report: critical,high,medium,low,info
                     (default: info)
    -o, --output     Output path for HTML report (default: reports/report_TIMESTAMP.html)
    -q, --quiet      Only show summary, not individual findings
    -h, --help       Show this help message
"""

import argparse
import io
import os
import sys
import time
from datetime import datetime

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanners.base import Severity, ScanResult
from scanners.registry import SCANNERS, by_key, code_scanners
from core.report_generator import (
    print_console_report,
    generate_html_report,
)
from core.scoring import calculate_score, get_grade


BANNER = r"""
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗  ║
  ║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝  ║
  ║   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║     ║
  ║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ║
  ║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║     ║
  ║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝     ║
  ║                                                           ║
  ║          ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗         ║
  ║         ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗        ║
  ║         ██║  ███╗██║   ██║███████║██████╔╝██║  ██║        ║
  ║         ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║        ║
  ║         ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝        ║
  ║          ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝         ║
  ║                                                           ║
  ║          🛡️  Project Security Analyzer  v1.0               ║
  ╚═══════════════════════════════════════════════════════════╝
"""

# Scanners come from the canonical registry. We accept the modern short keys
# (``static``, ``secrets``, ``deps``, ``config``, ``defaults``, ``attacks``,
# ``web``) plus a couple of legacy aliases so old shell scripts keep working.
LEGACY_ALIASES = {
    "dependencies": "deps",     # historical CLI key
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def parse_args():
    # Build the help string from the live registry so it can never lie.
    available = ", ".join(s.key for s in code_scanners())
    parser = argparse.ArgumentParser(
        description="Security Guard - Comprehensive Project Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python security_guard.py ./my_project --html --severity medium",
    )
    parser.add_argument("project_path", help="Path to the project directory to scan")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument(
        "--scanners",
        default="all",
        help=f"Comma-separated scanners (default: all). Available: {available}",
    )
    parser.add_argument(
        "--severity",
        default="info",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to report (default: info)",
    )
    parser.add_argument("-o", "--output", help="Output path for HTML report")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only show summary")
    return parser.parse_args()


def run_scanner(name: str, scanner_class, target_path: str) -> ScanResult:
    """Run a single scanner and return results."""
    print(f"  ▸ Running {name}...", end="", flush=True)
    scanner = scanner_class(target_path)
    result = scanner.scan()
    findings_count = len(result.findings)
    elapsed = result.scan_time_seconds

    if findings_count == 0:
        print(f" ✓ Clean ({elapsed:.1f}s)")
    else:
        print(f" ⚠ {findings_count} finding(s) ({elapsed:.1f}s)")

    return result


def filter_by_severity(results: list[ScanResult], min_severity: Severity) -> list[ScanResult]:
    """Filter findings by minimum severity."""
    min_score = min_severity.score
    for result in results:
        result.findings = [f for f in result.findings if f.severity.score >= min_score]
    return results


def main():
    args = parse_args()

    # Validate project path
    target_path = os.path.abspath(args.project_path)
    if not os.path.isdir(target_path):
        print(f"\n  ✗ Error: '{target_path}' is not a valid directory.")
        sys.exit(1)

    # Disable colors if requested
    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    # Print banner
    print(BANNER)
    print(f"  Target: {target_path}")
    print(f"  Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Determine which scanners to run.
    # Default ("all") = every "code" scanner; the "web" scanner needs a URL
    # and is silently excluded when the input is a filesystem path.
    registry = by_key()
    if args.scanners == "all":
        scanners_to_run = code_scanners()
    else:
        requested = [LEGACY_ALIASES.get(s.strip(), s.strip())
                     for s in args.scanners.split(",")]
        scanners_to_run = []
        for scanner_id in requested:
            entry = registry.get(scanner_id)
            if entry is None:
                print(f"  ⚠ Unknown scanner: {scanner_id} "
                      f"(available: {', '.join(registry)})")
                continue
            if entry.kind == "web":
                print(f"  ⚠ Skipping '{scanner_id}': the web auditor expects "
                      f"a URL, not a filesystem path.")
                continue
            scanners_to_run.append(entry)

    if not scanners_to_run:
        print("  ✗ No valid scanners specified.")
        sys.exit(1)

    # Run scanners
    print(f"  Running {len(scanners_to_run)} security scanner(s)...\n")
    scan_results = []
    total_start = time.time()

    for entry in scanners_to_run:
        result = run_scanner(entry.name, entry.cls, target_path)
        scan_results.append(result)

    total_time = time.time() - total_start
    print(f"\n  All scans completed in {total_time:.1f}s\n")

    # Filter by severity
    min_severity = SEVERITY_MAP[args.severity]
    scan_results = filter_by_severity(scan_results, min_severity)

    # Print console report
    if not args.quiet:
        score, grade = print_console_report(scan_results, target_path)
    else:
        # Quiet mode: just one summary line. Score uses the same canonical
        # function as the dashboard and PDF (core.scoring).
        all_findings = [f for sr in scan_results for f in sr.findings]
        score = calculate_score(all_findings)
        grade = get_grade(score)
        print(f"  Score: {score}/100 (Grade: {grade}) | Findings: {len(all_findings)}")

    # Generate HTML report
    if args.html:
        if args.output:
            output_path = args.output
        else:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            reports_dir = os.path.join(script_dir, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(reports_dir, f"security_report_{timestamp}.html")

        report_path = generate_html_report(scan_results, target_path, output_path)
        print(f"\n  📄 HTML report saved to: {report_path}")

    # Exit code based on score
    if score < 50:
        sys.exit(2)  # Critical security issues
    elif score < 70:
        sys.exit(1)  # Significant issues
    else:
        sys.exit(0)  # Acceptable


if __name__ == "__main__":
    main()
