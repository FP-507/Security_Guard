#!/usr/bin/env python3
"""Security Guard — Flask web server.

Serves the dashboard at ``/`` and exposes a small JSON API:

    GET  /api/scanners        list registered code scanners
    POST /api/scan            start a scan (local path | github URL | website URL)
    GET  /api/status          poll progress while a scan runs
    GET  /api/results         retrieve the JSON results of the last scan
    GET  /api/export/pdf      download the bilingual PDF report (?lang=es|en)

A single scan runs at a time in a background thread; ``scan_state`` is the
shared progress/results record polled by the front-end.

Three scan modes are auto-detected from the input:
    - **local**  : a filesystem path
    - **github** : any URL containing ``github.com/`` (uses :mod:`core.github_fetcher`)
    - **web**    : any other ``http(s)://`` URL (uses :class:`scanners.WebAuditor`)

GitHub mode supports private repositories via an optional Personal Access Token;
:class:`core.github_fetcher.PrivateRepoError` is propagated to the UI as a clear
"private repository" warning.
"""

import io
import json
import os
import sys
import threading
from datetime import datetime
from collections import Counter

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from flask import Flask, render_template, request, jsonify, send_file

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanners import (
    StaticAnalyzer,
    SecretDetector,
    DependencyScanner,
    ConfigAuditor,
    AttackSimulator,
    InsecureDefaultsScanner,
    WebAuditor,
)
from core.pdf_generator import generate_pdf
from scanners.base import Severity, ScanResult, Finding
from core import github_fetcher

app = Flask(__name__)

# ── Scanner registry ──────────────────────────────────────────────────────────
# Code scanners: for local paths and cloned GitHub repos
CODE_SCANNERS = [
    ("static",   "Static Code Analyzer",               StaticAnalyzer,          "Analyzes code for injection, XSS, crypto, and other vulnerability patterns"),
    ("secrets",  "Secret Detector",                    SecretDetector,          "Finds API keys, tokens, passwords, and high-entropy strings"),
    ("deps",     "Dependency Scanner",                  DependencyScanner,       "Checks packages against known CVE databases"),
    ("config",   "Config Auditor",                      ConfigAuditor,           "Reviews Docker, CI/CD, .gitignore, SSL, and server configs"),
    ("defaults", "Insecure Defaults (Trail of Bits)",   InsecureDefaultsScanner, "Detects fail-open patterns: fallback secrets, auth disabled by default, weak crypto in context"),
    ("attacks",  "Attack Simulator",                    AttackSimulator,         "Simulates SQL injection, XSS, CSRF, IDOR, SSRF, supply chain, and more"),
]

# Web scanner: for live websites
WEB_SCANNERS = [
    ("web", "Web Auditor", WebAuditor, "Black-box web scanner: security headers, cookies, CORS, XSS, open redirect, secret leakage, and more"),
]

# Combined registry used by /api/scanners
ALL_SCANNERS = CODE_SCANNERS + WEB_SCANNERS

# ── In-memory scan state ──────────────────────────────────────────────────────
scan_state = {
    "running": False,
    "progress": 0,
    "current_scanner": "",
    "results": None,
    "error": None,
    "scan_type": "local",   # "local" | "github" | "web"
}


# ── Helpers ───────────────────────────────────────────────────────────────────
def calculate_score(findings: list[dict]) -> float:
    penalty = 0
    for f in findings:
        sev = f["severity"]
        if sev == "CRITICAL":
            penalty += 15
        elif sev == "HIGH":
            penalty += 8
        elif sev == "MEDIUM":
            penalty += 4
        elif sev == "LOW":
            penalty += 2
        else:
            penalty += 0.5
    return round(max(0, 100 - penalty), 1)


def finding_to_dict(f: Finding) -> dict:
    return {
        "title": f.title,
        "severity": f.severity.value,
        "severity_score": f.severity.score,
        "category": f.category.value,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "code_snippet": f.code_snippet,
        "description": f.description,
        "root_cause": f.root_cause,
        "consequences": f.consequences,
        "recommendation": f.recommendation,
        "cwe_id": f.cwe_id,
        "attack_simulation": f.attack_simulation,
    }


# ── Scan thread ───────────────────────────────────────────────────────────────
def run_scan_thread(
    display_target: str,
    scan_path: str,
    scanner_keys: list[str],
    scan_type: str = "local",
    tmp_dir: str = None,
):
    """
    Core scan worker.

    Args:
        display_target: Human-readable name shown in results (URL, repo slug, or path basename)
        scan_path:      Actual path or URL passed to each scanner's constructor
        scanner_keys:   Which scanners to run (e.g. ["static","secrets","web"])
        scan_type:      "local" | "github" | "web"
        tmp_dir:        Temp directory to delete after scan (GitHub clones)
    """
    global scan_state
    try:
        scan_state["running"] = True
        scan_state["progress"] = 0
        scan_state["error"] = None
        scan_state["results"] = None
        scan_state["scan_type"] = scan_type

        registry = {s[0]: s for s in ALL_SCANNERS}
        selected = [registry[k] for k in scanner_keys if k in registry]

        all_findings = []
        scanner_results = []
        total = len(selected)

        for idx, (key, name, cls, desc) in enumerate(selected):
            scan_state["current_scanner"] = name
            scan_state["progress"] = int((idx / total) * 100)

            try:
                scanner = cls(scan_path)
                result = scanner.scan()
            except Exception as scanner_err:
                # Don't crash the whole scan if one scanner fails
                scanner_results.append({
                    "key": key,
                    "name": name,
                    "description": desc,
                    "files_scanned": 0,
                    "findings_count": 0,
                    "time": 0,
                    "error": str(scanner_err),
                })
                continue

            findings_dicts = [finding_to_dict(f) for f in result.findings]
            all_findings.extend(findings_dicts)

            scanner_results.append({
                "key": key,
                "name": name,
                "description": desc,
                "files_scanned": result.files_scanned,
                "findings_count": len(result.findings),
                "time": round(result.scan_time_seconds, 2),
            })

        score = calculate_score(all_findings)
        grade = (
            "A" if score >= 90 else
            "B" if score >= 80 else
            "C" if score >= 70 else
            "D" if score >= 60 else "F"
        )

        severity_counts = Counter(f["severity"] for f in all_findings)
        category_counts = Counter(f["category"] for f in all_findings)

        # Sort findings by severity score descending
        all_findings.sort(key=lambda f: f["severity_score"], reverse=True)

        scan_state["results"] = {
            "target": display_target,
            "scan_type": scan_type,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score": score,
            "grade": grade,
            "total_findings": len(all_findings),
            "severity_counts": {
                "CRITICAL": severity_counts.get("CRITICAL", 0),
                "HIGH":     severity_counts.get("HIGH", 0),
                "MEDIUM":   severity_counts.get("MEDIUM", 0),
                "LOW":      severity_counts.get("LOW", 0),
                "INFO":     severity_counts.get("INFO", 0),
            },
            "category_counts": dict(category_counts.most_common()),
            "scanners": scanner_results,
            "findings": all_findings,
        }
        scan_state["progress"] = 100
        scan_state["current_scanner"] = "Complete"

    except Exception as e:
        scan_state["error"] = str(e)
    finally:
        if tmp_dir:
            github_fetcher.cleanup_temp_dir(tmp_dir)
        scan_state["running"] = False


def run_github_scan_thread(url: str, scanner_keys: list[str], token: str = None):
    """Clone a GitHub repo then run code scanners on it."""
    global scan_state
    tmp_dir = None
    try:
        scan_state["running"] = True
        scan_state["progress"] = 0
        scan_state["error"] = None
        scan_state["results"] = None
        scan_state["scan_type"] = "github"

        # Parse display name before cloning
        info = github_fetcher.parse_github_url(url)
        display_target = info["display"]

        # Clone with progress updates
        def on_progress(msg: str):
            scan_state["current_scanner"] = msg

        scan_state["current_scanner"] = "Cloning repository..."
        tmp_dir = github_fetcher.clone_repo(url, token=token, progress_callback=on_progress)

        # Hand off to the core scan worker (won't re-set running/error/results)
        _run_scan_inner(display_target, tmp_dir, scanner_keys, "github", tmp_dir)
        tmp_dir = None  # ownership transferred; _run_scan_inner will clean up

    except Exception as e:
        scan_state["error"] = str(e)
        if tmp_dir:
            github_fetcher.cleanup_temp_dir(tmp_dir)
    finally:
        scan_state["running"] = False


def _run_scan_inner(
    display_target: str,
    scan_path: str,
    scanner_keys: list[str],
    scan_type: str,
    tmp_dir: str = None,
):
    """
    Same logic as run_scan_thread but does NOT touch scan_state["running"].
    Called by run_github_scan_thread after cloning is done.
    """
    global scan_state
    try:
        registry = {s[0]: s for s in ALL_SCANNERS}
        selected = [registry[k] for k in scanner_keys if k in registry]

        all_findings = []
        scanner_results = []
        total = len(selected)

        for idx, (key, name, cls, desc) in enumerate(selected):
            scan_state["current_scanner"] = name
            scan_state["progress"] = int((idx / total) * 100)

            try:
                scanner = cls(scan_path)
                result = scanner.scan()
            except Exception as scanner_err:
                scanner_results.append({
                    "key": key, "name": name, "description": desc,
                    "files_scanned": 0, "findings_count": 0, "time": 0,
                    "error": str(scanner_err),
                })
                continue

            findings_dicts = [finding_to_dict(f) for f in result.findings]
            all_findings.extend(findings_dicts)
            scanner_results.append({
                "key": key,
                "name": name,
                "description": desc,
                "files_scanned": result.files_scanned,
                "findings_count": len(result.findings),
                "time": round(result.scan_time_seconds, 2),
            })

        score = calculate_score(all_findings)
        grade = (
            "A" if score >= 90 else
            "B" if score >= 80 else
            "C" if score >= 70 else
            "D" if score >= 60 else "F"
        )

        severity_counts = Counter(f["severity"] for f in all_findings)
        category_counts = Counter(f["category"] for f in all_findings)
        all_findings.sort(key=lambda f: f["severity_score"], reverse=True)

        scan_state["results"] = {
            "target": display_target,
            "scan_type": scan_type,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score": score,
            "grade": grade,
            "total_findings": len(all_findings),
            "severity_counts": {
                "CRITICAL": severity_counts.get("CRITICAL", 0),
                "HIGH":     severity_counts.get("HIGH", 0),
                "MEDIUM":   severity_counts.get("MEDIUM", 0),
                "LOW":      severity_counts.get("LOW", 0),
                "INFO":     severity_counts.get("INFO", 0),
            },
            "category_counts": dict(category_counts.most_common()),
            "scanners": scanner_results,
            "findings": all_findings,
        }
        scan_state["progress"] = 100
        scan_state["current_scanner"] = "Complete"

    finally:
        if tmp_dir:
            github_fetcher.cleanup_temp_dir(tmp_dir)


# ── Flask routes ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    if scan_state["running"]:
        return jsonify({"error": "A scan is already running"}), 409

    data = request.json or {}
    raw = data.get("path", "").strip()
    if not raw:
        return jsonify({"error": "No target provided"}), 400

    github_token = data.get("github_token", "").strip() or None

    # ── Route by input type ───────────────────────────────────────────────────
    if github_fetcher.is_github_url(raw):
        # GitHub repository — clone then scan code
        scanner_keys = data.get(
            "scanners", ["static", "secrets", "deps", "config", "defaults", "attacks"]
        )
        thread = threading.Thread(
            target=run_github_scan_thread,
            args=(raw, scanner_keys, github_token),
            daemon=True,
        )
        thread.start()
        return jsonify({"status": "started", "scan_type": "github", "target": raw})

    elif github_fetcher.is_web_url(raw):
        # Live website — black-box web audit only
        thread = threading.Thread(
            target=run_scan_thread,
            args=(raw, raw, ["web"], "web", None),
            daemon=True,
        )
        thread.start()
        return jsonify({"status": "started", "scan_type": "web", "target": raw})

    else:
        # Local directory — full code scan
        if not os.path.isdir(raw):
            return jsonify({"error": f"Invalid directory: {raw}"}), 400
        scanner_keys = data.get(
            "scanners", ["static", "secrets", "deps", "config", "defaults", "attacks"]
        )
        thread = threading.Thread(
            target=run_scan_thread,
            args=(raw, raw, scanner_keys, "local", None),
            daemon=True,
        )
        thread.start()
        return jsonify({"status": "started", "scan_type": "local", "target": raw})


@app.route("/api/status")
def scan_status():
    return jsonify({
        "running": scan_state["running"],
        "progress": scan_state["progress"],
        "current_scanner": scan_state["current_scanner"],
        "error": scan_state["error"],
        "has_results": scan_state["results"] is not None,
        "scan_type": scan_state["scan_type"],
    })


@app.route("/api/results")
def scan_results():
    if scan_state["results"] is None:
        return jsonify({"error": "No scan results available"}), 404
    return jsonify(scan_state["results"])


@app.route("/api/scanners")
def list_scanners():
    """Return code scanners (for the toggle UI). Web scanner is automatic."""
    return jsonify([
        {"key": k, "name": n, "description": d}
        for k, n, _, d in CODE_SCANNERS
    ])


@app.route("/api/export/pdf")
def export_pdf():
    if scan_state["results"] is None:
        return jsonify({"error": "No scan results available"}), 404

    lang = request.args.get("lang", "es")
    if lang not in ("es", "en"):
        lang = "es"

    try:
        pdf_bytes = generate_pdf(scan_state["results"], lang=lang)
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {e}"}), 500

    target_name = scan_state["results"].get("target", "project")
    # Sanitize for filename
    target_name = target_name.replace("https://", "").replace("http://", "")
    target_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in target_name)
    target_name = target_name[:40]
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_report_{target_name}_{date_str}_{lang}.pdf"

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


if __name__ == "__main__":
    print("\n  🛡️  Security Guard - Web Interface")
    print("  http://localhost:5000\n")
    app.run(debug=False, host="127.0.0.1", port=5000)
