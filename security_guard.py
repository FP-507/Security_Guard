#!/usr/bin/env python3
"""
Security Guard - Comprehensive Project Security Analyzer
=========================================================

Analyzes a project directory for security vulnerabilities, simulates attacks,
and provides actionable remediation recommendations to reach 90% security.

Usage:
    python security_guard.py <project_path> [options]

Options:
    --html           Generate HTML report (saved to reports/)
    --no-color       Disable colored output
    --scanners       Comma-separated list of scanners to run:
                     static,secrets,dependencies,config,attacks (default: all)
    --severity       Minimum severity to report: critical,high,medium,low,info (default: info)
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

from scanners import (
    StaticAnalyzer,
    SecretDetector,
    DependencyScanner,
    ConfigAuditor,
    AttackSimulator,
)
from scanners.base import Severity, ScanResult
from report_generator import (
    print_console_report,
    generate_html_report,
    calculate_security_score,
    get_grade,
)


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

SCANNER_MAP = {
    "static": ("Static Code Analyzer", StaticAnalyzer),
    "secrets": ("Secret Detector", SecretDetector),
    "dependencies": ("Dependency Scanner", DependencyScanner),
    "config": ("Configuration Auditor", ConfigAuditor),
    "attacks": ("Attack Simulator", AttackSimulator),
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def parse_args():
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
        help="Comma-separated scanners: static,secrets,dependencies,config,attacks (default: all)",
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

    # Determine which scanners to run
    if args.scanners == "all":
        scanners_to_run = list(SCANNER_MAP.items())
    else:
        scanner_names = [s.strip() for s in args.scanners.split(",")]
        scanners_to_run = []
        for name in scanner_names:
            if name in SCANNER_MAP:
                scanners_to_run.append((name, SCANNER_MAP[name]))
            else:
                print(f"  ⚠ Unknown scanner: {name}")

    if not scanners_to_run:
        print("  ✗ No valid scanners specified.")
        sys.exit(1)

    # Run scanners
    print(f"  Running {len(scanners_to_run)} security scanner(s)...\n")
    scan_results = []
    total_start = time.time()

    for key, (display_name, scanner_class) in scanners_to_run:
        result = run_scanner(display_name, scanner_class, target_path)
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
        all_findings = []
        for sr in scan_results:
            all_findings.extend(sr.findings)
        score = calculate_security_score(all_findings)
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
