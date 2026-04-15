"""Report generator - produces console and HTML reports with security score."""

import html
import os
from datetime import datetime
from collections import Counter

from scanners.base import Finding, ScanResult, Severity, Category


# ─── Security Score Calculation ────────────────────────────────────────────

def calculate_security_score(all_findings: list[Finding]) -> float:
    """Calculate security score (0-100) based on findings.

    The score starts at 100 and is reduced based on the number and severity
    of findings. The goal is to reach approximately 90% after applying fixes.
    """
    if not all_findings:
        return 100.0

    penalty = 0
    for f in all_findings:
        if f.severity == Severity.CRITICAL:
            penalty += 15
        elif f.severity == Severity.HIGH:
            penalty += 8
        elif f.severity == Severity.MEDIUM:
            penalty += 4
        elif f.severity == Severity.LOW:
            penalty += 2
        elif f.severity == Severity.INFO:
            penalty += 0.5

    # Cap penalty at 100
    score = max(0, 100 - penalty)
    return round(score, 1)


def get_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# ─── Console Report ───────────────────────────────────────────────────────

SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91m",  # Red
    Severity.HIGH: "\033[93m",      # Yellow
    Severity.MEDIUM: "\033[33m",    # Orange-ish
    Severity.LOW: "\033[36m",       # Cyan
    Severity.INFO: "\033[37m",      # White
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

    # Header
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  🛡️  SECURITY GUARD - Audit Report{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"  Target:  {target_path}")
    print(f"  Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Files:   {total_files} scanned in {total_time:.1f}s")
    print(f"{BOLD}{'='*70}{RESET}")

    # Score
    score_color = GREEN if score >= 90 else YELLOW if score >= 70 else RED
    print(f"\n  {BOLD}SECURITY SCORE: {score_color}{score}/100 (Grade: {grade}){RESET}")

    bar_width = 40
    filled = int(bar_width * score / 100)
    bar = "█" * filled + "░" * (bar_width - filled)
    print(f"  [{score_color}{bar}{RESET}]")

    # Summary counts
    severity_counts = Counter(f.severity for f in all_findings)
    print(f"\n  {BOLD}FINDINGS SUMMARY:{RESET}")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = severity_counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        icon = "●" if count > 0 else "○"
        print(f"    {color}{icon} {sev.value:10s}: {count}{RESET}")

    print(f"\n    Total findings: {len(all_findings)}")

    # Category breakdown
    category_counts = Counter(f.category for f in all_findings)
    if category_counts:
        print(f"\n  {BOLD}OWASP CATEGORIES:{RESET}")
        for cat, count in category_counts.most_common():
            print(f"    {DIM}▸{RESET} {cat.value}: {count}")

    # Detailed findings
    if all_findings:
        print(f"\n{BOLD}{'─'*70}{RESET}")
        print(f"{BOLD}  DETAILED FINDINGS{RESET}")
        print(f"{BOLD}{'─'*70}{RESET}")

        # Sort by severity
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

    # Remediation roadmap
    print(f"\n{BOLD}{'─'*70}{RESET}")
    print(f"{BOLD}  REMEDIATION ROADMAP TO 90% SECURITY{RESET}")
    print(f"{BOLD}{'─'*70}{RESET}")

    target_score = 90.0
    if score >= target_score:
        print(f"\n  {GREEN}✓ Your project already meets the 90% security target!{RESET}")
        print(f"  {GREEN}  Continue monitoring for new vulnerabilities.{RESET}")
    else:
        points_needed = target_score - score
        print(f"\n  Current: {score_color}{score}%{RESET} → Target: {GREEN}90%{RESET} (need +{points_needed:.0f} points)")
        print()

        # Priority actions
        priority = 1
        critical_count = severity_counts.get(Severity.CRITICAL, 0)
        high_count = severity_counts.get(Severity.HIGH, 0)
        medium_count = severity_counts.get(Severity.MEDIUM, 0)

        if critical_count:
            potential = min(critical_count * 15, points_needed)
            print(f"  {RED}Priority {priority}: Fix {critical_count} CRITICAL issues (+{potential:.0f} points){RESET}")
            print(f"    These are exploitable vulnerabilities that need immediate attention.")
            priority += 1

        if high_count:
            potential = min(high_count * 8, max(0, points_needed - critical_count * 15))
            print(f"  {YELLOW}Priority {priority}: Fix {high_count} HIGH issues (+{potential:.0f} points){RESET}")
            print(f"    These represent significant security risks.")
            priority += 1

        if medium_count and score + critical_count * 15 + high_count * 8 < target_score:
            potential = min(medium_count * 4, max(0, points_needed - critical_count * 15 - high_count * 8))
            print(f"  {WHITE}Priority {priority}: Fix {medium_count} MEDIUM issues (+{potential:.0f} points){RESET}")
            print(f"    These are best-practice improvements.")
            priority += 1

        # General recommendations
        print(f"\n  {BOLD}General Security Recommendations:{RESET}")
        general_recs = [
            "Implement automated dependency scanning in CI/CD (pip-audit, npm audit)",
            "Add pre-commit hooks for secret detection (detect-secrets)",
            "Enable security linters in your IDE (bandit for Python, ESLint security plugin)",
            "Conduct regular penetration testing",
            "Implement security headers (Helmet.js, Django SecurityMiddleware)",
            "Set up error monitoring that doesn't expose stack traces to users",
            "Review and rotate all exposed credentials immediately",
        ]
        for rec in general_recs:
            print(f"    {DIM}▸{RESET} {rec}")

    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  Security Guard scan complete.{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")

    return score, grade


# ─── HTML Report ──────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Guard - Audit Report</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-dim: #8b949e;
    --critical: #f85149; --high: #f0883e; --medium: #d29922;
    --low: #58a6ff; --info: #8b949e; --green: #3fb950;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
  .container { max-width: 1100px; margin: 0 auto; padding: 2rem; }

  .header { text-align: center; padding: 2rem 0; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
  .header h1 { font-size: 2rem; margin-bottom: 0.5rem; }
  .header .subtitle { color: var(--text-dim); }

  .score-section { text-align: center; padding: 2rem; background: var(--surface); border-radius: 12px; margin-bottom: 2rem; border: 1px solid var(--border); }
  .score-value { font-size: 4rem; font-weight: 700; }
  .score-grade { font-size: 1.5rem; color: var(--text-dim); }
  .score-bar { width: 100%%; max-width: 400px; height: 12px; background: var(--border); border-radius: 6px; margin: 1rem auto; overflow: hidden; }
  .score-fill { height: 100%%; border-radius: 6px; transition: width 1s ease; }

  .score-a .score-value, .score-a .score-fill { color: var(--green); background: var(--green); }
  .score-b .score-value, .score-b .score-fill { color: var(--low); background: var(--low); }
  .score-c .score-value, .score-c .score-fill { color: var(--medium); background: var(--medium); }
  .score-d .score-value, .score-d .score-fill { color: var(--high); background: var(--high); }
  .score-f .score-value, .score-f .score-fill { color: var(--critical); background: var(--critical); }

  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .summary-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .summary-card .count { font-size: 2rem; font-weight: 700; }
  .summary-card .label { color: var(--text-dim); font-size: 0.85rem; }
  .severity-critical .count { color: var(--critical); }
  .severity-high .count { color: var(--high); }
  .severity-medium .count { color: var(--medium); }
  .severity-low .count { color: var(--low); }
  .severity-info .count { color: var(--info); }

  .section-title { font-size: 1.3rem; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }

  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
  .finding-header { padding: 1rem; cursor: pointer; display: flex; align-items: center; gap: 0.75rem; }
  .finding-header:hover { background: rgba(255,255,255,0.03); }
  .severity-badge { padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .badge-critical { background: rgba(248,81,73,0.2); color: var(--critical); border: 1px solid var(--critical); }
  .badge-high { background: rgba(240,136,62,0.2); color: var(--high); border: 1px solid var(--high); }
  .badge-medium { background: rgba(210,153,34,0.2); color: var(--medium); border: 1px solid var(--medium); }
  .badge-low { background: rgba(88,166,255,0.2); color: var(--low); border: 1px solid var(--low); }
  .badge-info { background: rgba(139,148,158,0.2); color: var(--info); border: 1px solid var(--info); }
  .finding-title { font-weight: 600; flex: 1; }
  .finding-file { color: var(--text-dim); font-size: 0.85rem; font-family: monospace; }

  .finding-body { padding: 0 1rem 1rem; display: none; }
  .finding.open .finding-body { display: block; }
  .finding-detail { margin-bottom: 0.75rem; }
  .finding-detail strong { color: var(--text-dim); font-size: 0.85rem; display: block; margin-bottom: 0.25rem; }
  code { background: rgba(255,255,255,0.08); padding: 0.2rem 0.5rem; border-radius: 4px; font-family: 'Fira Code', monospace; font-size: 0.85rem; word-break: break-all; }
  pre { background: rgba(255,255,255,0.05); padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; white-space: pre-wrap; }
  .attack-box { background: rgba(248,81,73,0.08); border: 1px solid rgba(248,81,73,0.3); border-radius: 6px; padding: 1rem; }
  .recommendation-box { background: rgba(63,185,80,0.08); border: 1px solid rgba(63,185,80,0.3); border-radius: 6px; padding: 1rem; }

  .roadmap { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-top: 1rem; }
  .roadmap-step { display: flex; gap: 1rem; padding: 0.75rem 0; border-bottom: 1px solid var(--border); }
  .roadmap-step:last-child { border-bottom: none; }
  .step-num { width: 32px; height: 32px; background: var(--border); border-radius: 50%%; display: flex; align-items: center; justify-content: center; font-weight: 700; flex-shrink: 0; }

  .footer { text-align: center; padding: 2rem 0; color: var(--text-dim); font-size: 0.85rem; border-top: 1px solid var(--border); margin-top: 2rem; }

  .toggle { cursor: pointer; user-select: none; color: var(--text-dim); }
  .toggle::before { content: "▸ "; }
  .finding.open .toggle::before { content: "▾ "; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ Security Guard</h1>
    <p class="subtitle">Security Audit Report</p>
    <p class="subtitle">{{target_path}} &mdash; {{date}}</p>
    <p class="subtitle">{{total_files}} files scanned in {{scan_time}}s</p>
  </div>

  <div class="score-section score-{{grade_lower}}">
    <div class="score-value">{{score}}/100</div>
    <div class="score-grade">Grade: {{grade}}</div>
    <div class="score-bar"><div class="score-fill" style="width:{{score}}%%"></div></div>
  </div>

  <div class="summary">
    <div class="summary-card severity-critical"><div class="count">{{critical_count}}</div><div class="label">CRITICAL</div></div>
    <div class="summary-card severity-high"><div class="count">{{high_count}}</div><div class="label">HIGH</div></div>
    <div class="summary-card severity-medium"><div class="count">{{medium_count}}</div><div class="label">MEDIUM</div></div>
    <div class="summary-card severity-low"><div class="count">{{low_count}}</div><div class="label">LOW</div></div>
    <div class="summary-card severity-info"><div class="count">{{info_count}}</div><div class="label">INFO</div></div>
  </div>

  <h2 class="section-title">Findings ({{total_findings}})</h2>
  {{findings_html}}

  <h2 class="section-title">Remediation Roadmap to 90%%</h2>
  <div class="roadmap">
    {{roadmap_html}}
  </div>

  <div class="footer">
    <p>Generated by Security Guard &mdash; {{date}}</p>
    <p>This report is for authorized security assessment purposes only.</p>
  </div>
</div>
<script>
document.querySelectorAll('.finding-header').forEach(h => {
  h.addEventListener('click', () => h.parentElement.classList.toggle('open'));
});
</script>
</body>
</html>"""


def generate_html_report(scan_results: list[ScanResult], target_path: str, output_path: str) -> str:
    """Generate an HTML report file and return the file path."""
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

    # Sort findings by severity
    sorted_findings = sorted(all_findings, key=lambda f: f.severity.score, reverse=True)

    # Build findings HTML
    findings_html_parts = []
    for i, f in enumerate(sorted_findings, 1):
        badge_class = f"badge-{f.severity.value.lower()}"
        file_info = f.file_path + (f":{f.line_number}" if f.line_number else "")

        attack_html = ""
        if f.attack_simulation:
            attack_html = f"""
            <div class="finding-detail">
                <strong>Attack Simulation</strong>
                <div class="attack-box"><pre>{html.escape(f.attack_simulation)}</pre></div>
            </div>"""

        cwe_html = f"<code>{html.escape(f.cwe_id)}</code>" if f.cwe_id else ""

        findings_html_parts.append(f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity-badge {badge_class}">{f.severity.value}</span>
                <span class="finding-title">#{i} {html.escape(f.title)}</span>
                <span class="finding-file">{html.escape(file_info)}</span>
                <span class="toggle"></span>
            </div>
            <div class="finding-body">
                <div class="finding-detail"><strong>Category</strong>{html.escape(f.category.value)} {cwe_html}</div>
                <div class="finding-detail"><strong>Code</strong><code>{html.escape(f.code_snippet)}</code></div>
                <div class="finding-detail"><strong>Description</strong><p>{html.escape(f.description)}</p></div>
                {attack_html}
                <div class="finding-detail">
                    <strong>Recommendation</strong>
                    <div class="recommendation-box">{html.escape(f.recommendation)}</div>
                </div>
            </div>
        </div>""")

    # Build roadmap HTML
    roadmap_parts = []
    step = 1
    critical_count = severity_counts.get(Severity.CRITICAL, 0)
    high_count = severity_counts.get(Severity.HIGH, 0)
    medium_count = severity_counts.get(Severity.MEDIUM, 0)

    if score >= 90:
        roadmap_parts.append(f"""
        <div class="roadmap-step">
            <div class="step-num">✓</div>
            <div>
                <strong>Your project meets the 90%% security target!</strong>
                <p>Continue monitoring for new vulnerabilities and keep dependencies updated.</p>
            </div>
        </div>""")
    else:
        if critical_count:
            roadmap_parts.append(f"""
            <div class="roadmap-step">
                <div class="step-num" style="background:var(--critical);color:white">{step}</div>
                <div>
                    <strong>Fix {critical_count} CRITICAL vulnerabilities (highest priority)</strong>
                    <p>These are actively exploitable and must be fixed immediately. Each fix recovers ~15 points.</p>
                </div>
            </div>""")
            step += 1

        if high_count:
            roadmap_parts.append(f"""
            <div class="roadmap-step">
                <div class="step-num" style="background:var(--high);color:white">{step}</div>
                <div>
                    <strong>Fix {high_count} HIGH severity issues</strong>
                    <p>These represent significant risk and should be addressed in the next sprint. Each fix recovers ~8 points.</p>
                </div>
            </div>""")
            step += 1

        if medium_count:
            roadmap_parts.append(f"""
            <div class="roadmap-step">
                <div class="step-num" style="background:var(--medium);color:white">{step}</div>
                <div>
                    <strong>Address {medium_count} MEDIUM findings</strong>
                    <p>Best-practice improvements that harden the application. Each fix recovers ~4 points.</p>
                </div>
            </div>""")
            step += 1

        roadmap_parts.append(f"""
        <div class="roadmap-step">
            <div class="step-num" style="background:var(--green);color:white">{step}</div>
            <div>
                <strong>Implement preventive measures</strong>
                <p>Add CI/CD security scanning, pre-commit hooks, dependency auditing, and regular penetration testing.</p>
            </div>
        </div>""")

    # Fill template
    report_html = HTML_TEMPLATE
    replacements = {
        "{{target_path}}": html.escape(target_path),
        "{{date}}": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "{{total_files}}": str(total_files),
        "{{scan_time}}": f"{total_time:.1f}",
        "{{score}}": str(score),
        "{{grade}}": grade,
        "{{grade_lower}}": grade.lower(),
        "{{critical_count}}": str(critical_count),
        "{{high_count}}": str(high_count),
        "{{medium_count}}": str(medium_count),
        "{{low_count}}": str(severity_counts.get(Severity.LOW, 0)),
        "{{info_count}}": str(severity_counts.get(Severity.INFO, 0)),
        "{{total_findings}}": str(len(all_findings)),
        "{{findings_html}}": "\n".join(findings_html_parts),
        "{{roadmap_html}}": "\n".join(roadmap_parts),
    }

    for key, value in replacements.items():
        report_html = report_html.replace(key, value)

    # Write to file
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)

    return output_path
