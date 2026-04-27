"""Report generator — produces console and HTML reports with security score.

Score and grade come from :mod:`core.scoring` (single source of truth) so the
CLI, web dashboard and PDF report always agree.
"""

import html
import os
from datetime import datetime
from collections import Counter

from scanners.base import Finding, ScanResult, Severity, Category
from .scoring import calculate_score, get_grade


# Backwards-compatible alias — older callers imported this name from here.
# New code should import :func:`core.scoring.calculate_score` directly.
def calculate_security_score(all_findings: list[Finding]) -> float:
    """Compatibility wrapper around :func:`core.scoring.calculate_score`."""
    return calculate_score(all_findings)


# ─── Console Report ───────────────────────────────────────────────────────

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[93m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
DIM = "\033[2m"


def print_console_report(scan_results: list[ScanResult], target_path: str):
    """Print a formatted console report."""
    all_findings = []
    total_files = 0
    total_time = 0.0

    for sr in scan_results:
        all_findings.extend(sr.findings)
        total_files += sr.files_scanned
        total_time += sr.scan_time_seconds

    score = calculate_security_score(all_findings)
    grade = get_grade(score)

    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  🛡️  SECURITY GUARD - Audit Report{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"  Target:  {target_path}")
    print(f"  Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Files:   {total_files} scanned in {total_time:.1f}s")
    print(f"{BOLD}{'='*70}{RESET}")

    score_color = GREEN if score >= 90 else YELLOW if score >= 70 else RED
    print(f"\n  {BOLD}SECURITY SCORE: {score_color}{score}/100 (Grade: {grade}){RESET}")

    bar_width = 40
    filled = int(bar_width * score / 100)
    bar = "█" * filled + "░" * (bar_width - filled)
    print(f"  [{score_color}{bar}{RESET}]")

    severity_counts = Counter(f.severity for f in all_findings)
    print(f"\n  {BOLD}FINDINGS SUMMARY:{RESET}")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = severity_counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        icon = "●" if count > 0 else "○"
        print(f"    {color}{icon} {sev.value:10s}: {count}{RESET}")

    print(f"\n    Total findings: {len(all_findings)}")

    category_counts = Counter(f.category for f in all_findings)
    if category_counts:
        print(f"\n  {BOLD}OWASP CATEGORIES:{RESET}")
        for cat, count in category_counts.most_common():
            print(f"    {DIM}▸{RESET} {cat.value}: {count}")

    if all_findings:
        print(f"\n{BOLD}{'─'*70}{RESET}")
        print(f"{BOLD}  DETAILED FINDINGS{RESET}")
        print(f"{BOLD}{'─'*70}{RESET}")

        sorted_findings = sorted(all_findings, key=lambda f: f.severity.score, reverse=True)

        for i, f in enumerate(sorted_findings, 1):
            color = SEVERITY_COLORS[f.severity]
            print(f"\n  {color}{BOLD}[{f.severity.value}]{RESET} {BOLD}#{i} {f.title}{RESET}")
            if f.cwe_id:
                print(f"    {DIM}CWE: {f.cwe_id}{RESET}")
            print(f"    {DIM}File: {f.file_path}" + (f":{f.line_number}" if f.line_number else "") + f"{RESET}")
            print(f"    {DIM}Category: {f.category.value}{RESET}")
            print(f"\n    {WHITE}Code:{RESET} {f.code_snippet}")
            print(f"\n    {WHITE}Description:{RESET}")
            for desc_line in f.description.split("\n"):
                print(f"      {desc_line}")

            if f.attack_simulation:
                print(f"\n    {RED}Attack Simulation:{RESET}")
                for atk_line in f.attack_simulation.split("\n"):
                    print(f"      {atk_line}")

            print(f"\n    {GREEN}Recommendation:{RESET}")
            for rec_line in f.recommendation.split("\n"):
                print(f"      {rec_line}")

    print(f"\n{BOLD}{'─'*70}{RESET}")
    print(f"{BOLD}  REMEDIATION ROADMAP TO 90% SECURITY{RESET}")
    print(f"{BOLD}{'─'*70}{RESET}")

    target_score = 90.0
    if score >= target_score:
        print(f"\n  {GREEN}✓ Your project already meets the 90% security target!{RESET}")
    else:
        points_needed = target_score - score
        print(f"\n  Current: {score_color}{score}%{RESET} → Target: {GREEN}90%{RESET} (need +{points_needed:.0f} points)\n")

        priority = 1
        critical_count = severity_counts.get(Severity.CRITICAL, 0)
        high_count = severity_counts.get(Severity.HIGH, 0)
        medium_count = severity_counts.get(Severity.MEDIUM, 0)

        if critical_count:
            print(f"  {RED}Priority {priority}: Fix {critical_count} CRITICAL issues{RESET}")
            priority += 1
        if high_count:
            print(f"  {YELLOW}Priority {priority}: Fix {high_count} HIGH issues{RESET}")
            priority += 1
        if medium_count:
            print(f"  {WHITE}Priority {priority}: Address {medium_count} MEDIUM findings{RESET}")

    print(f"\n{BOLD}{'='*70}{RESET}\n")
    return score, grade


# ─── HTML Report ──────────────────────────────────────────────────────────

def generate_html_report(scan_results: list[ScanResult], target_path: str, output_path: str) -> str:
    """Generate an HTML report and return the output file path."""
    all_findings = []
    total_files = 0
    total_time = 0.0

    for sr in scan_results:
        all_findings.extend(sr.findings)
        total_files += sr.files_scanned
        total_time += sr.scan_time_seconds

    score = calculate_security_score(all_findings)
    grade = get_grade(score)
    severity_counts = Counter(f.severity for f in all_findings)
    sorted_findings = sorted(all_findings, key=lambda f: f.severity.score, reverse=True)

    findings_parts = []
    for i, f in enumerate(sorted_findings, 1):
        badge = f"badge-{f.severity.value.lower()}"
        file_info = f.file_path + (f":{f.line_number}" if f.line_number else "")
        atk = (f'<div class="finding-detail"><strong>Attack Simulation</strong>'
               f'<pre class="attack-box">{html.escape(f.attack_simulation)}</pre></div>'
               if f.attack_simulation else "")
        findings_parts.append(f"""
<div class="finding">
  <div class="finding-header">
    <span class="severity-badge {badge}">{f.severity.value}</span>
    <span class="finding-title">#{i} {html.escape(f.title)}</span>
    <span class="finding-file">{html.escape(file_info)}</span>
  </div>
  <div class="finding-body">
    <p><strong>Category:</strong> {html.escape(f.category.value)}</p>
    <p><strong>Code:</strong> <code>{html.escape(f.code_snippet)}</code></p>
    <p>{html.escape(f.description)}</p>
    {atk}
    <div class="rec-box">{html.escape(f.recommendation)}</div>
  </div>
</div>""")

    findings_html = "\n".join(findings_parts) if findings_parts else "<p>No findings.</p>"

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><title>Security Guard Report</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:2rem}}
.container{{max-width:1100px;margin:0 auto}}
h1{{text-align:center;margin-bottom:1rem}}
.score{{text-align:center;font-size:3rem;font-weight:700;margin:1rem 0}}
.finding{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin:.75rem 0;overflow:hidden}}
.finding-header{{padding:.75rem 1rem;cursor:pointer;display:flex;gap:.75rem;align-items:center}}
.finding-header:hover{{background:rgba(255,255,255,.04)}}
.finding-body{{padding:.75rem 1rem 1rem;display:none;border-top:1px solid #30363d}}
.finding.open .finding-body{{display:block}}
.severity-badge{{padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:600;text-transform:uppercase}}
.badge-critical{{background:rgba(248,81,73,.2);color:#f85149}}
.badge-high{{background:rgba(240,136,62,.2);color:#f0883e}}
.badge-medium{{background:rgba(210,153,34,.2);color:#d29922}}
.badge-low{{background:rgba(88,166,255,.2);color:#58a6ff}}
.badge-info{{background:rgba(139,148,158,.2);color:#8b949e}}
.finding-title{{flex:1;font-weight:600}}
.finding-file{{font-family:monospace;font-size:.85rem;color:#8b949e}}
.rec-box{{background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.3);border-radius:6px;padding:.75rem;margin-top:.5rem}}
.attack-box{{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.3);border-radius:6px;padding:.75rem;white-space:pre-wrap;font-size:.85rem}}
code{{background:rgba(255,255,255,.08);padding:.1rem .4rem;border-radius:4px;font-family:monospace}}
</style>
</head>
<body>
<div class="container">
<h1>🛡️ Security Guard Report</h1>
<p style="text-align:center;color:#8b949e">{html.escape(target_path)} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — {total_files} files in {total_time:.1f}s</p>
<div class="score">{score}/100 — Grade {grade}</div>
<h2>Findings ({len(all_findings)})</h2>
{findings_html}
</div>
<script>
document.querySelectorAll('.finding-header').forEach(h=>h.addEventListener('click',()=>h.parentElement.classList.toggle('open')));
</script>
</body></html>"""

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(report_html)
    return output_path
