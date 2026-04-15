#!/usr/bin/env python3
"""Security Guard - Web Interface"""

import io
import json
import os
import sys
import time
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
)
from pdf_generator import generate_pdf
from scanners.base import Severity, ScanResult, Finding

app = Flask(__name__)

# In-memory scan state
scan_state = {
    "running": False,
    "progress": 0,
    "current_scanner": "",
    "results": None,
    "error": None,
}

SCANNERS = [
    ("static", "Static Code Analyzer", StaticAnalyzer, "Analyzes code for injection, XSS, crypto, and other vulnerability patterns"),
    ("secrets", "Secret Detector", SecretDetector, "Finds API keys, tokens, passwords, and high-entropy strings"),
    ("dependencies", "Dependency Scanner", DependencyScanner, "Checks packages against known CVE databases"),
    ("config", "Config Auditor", ConfigAuditor, "Reviews Docker, CI/CD, .gitignore, SSL, and server configs"),
    ("attacks", "Attack Simulator", AttackSimulator, "Simulates SQL injection, XSS, CSRF, IDOR, and more"),
]


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
        "recommendation": f.recommendation,
        "cwe_id": f.cwe_id,
        "attack_simulation": f.attack_simulation,
    }


def run_scan_thread(target_path: str, scanner_keys: list[str]):
    global scan_state
    try:
        scan_state["running"] = True
        scan_state["progress"] = 0
        scan_state["error"] = None
        scan_state["results"] = None

        selected = [s for s in SCANNERS if s[0] in scanner_keys]
        all_findings = []
        scanner_results = []
        total = len(selected)

        for idx, (key, name, cls, desc) in enumerate(selected):
            scan_state["current_scanner"] = name
            scan_state["progress"] = int((idx / total) * 100)

            scanner = cls(target_path)
            result = scanner.scan()

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
        grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

        severity_counts = Counter(f["severity"] for f in all_findings)
        category_counts = Counter(f["category"] for f in all_findings)

        # Sort findings by severity score descending
        all_findings.sort(key=lambda f: f["severity_score"], reverse=True)

        scan_state["results"] = {
            "target": target_path,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score": score,
            "grade": grade,
            "total_findings": len(all_findings),
            "severity_counts": {
                "CRITICAL": severity_counts.get("CRITICAL", 0),
                "HIGH": severity_counts.get("HIGH", 0),
                "MEDIUM": severity_counts.get("MEDIUM", 0),
                "LOW": severity_counts.get("LOW", 0),
                "INFO": severity_counts.get("INFO", 0),
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
        scan_state["running"] = False


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    if scan_state["running"]:
        return jsonify({"error": "A scan is already running"}), 409

    data = request.json
    target_path = data.get("path", "").strip()

    if not target_path or not os.path.isdir(target_path):
        return jsonify({"error": f"Invalid directory: {target_path}"}), 400

    scanner_keys = data.get("scanners", ["static", "secrets", "dependencies", "config", "attacks"])

    thread = threading.Thread(target=run_scan_thread, args=(target_path, scanner_keys), daemon=True)
    thread.start()

    return jsonify({"status": "started", "path": target_path})


@app.route("/api/status")
def scan_status():
    return jsonify({
        "running": scan_state["running"],
        "progress": scan_state["progress"],
        "current_scanner": scan_state["current_scanner"],
        "error": scan_state["error"],
        "has_results": scan_state["results"] is not None,
    })


@app.route("/api/results")
def scan_results():
    if scan_state["results"] is None:
        return jsonify({"error": "No scan results available"}), 404
    return jsonify(scan_state["results"])


@app.route("/api/scanners")
def list_scanners():
    return jsonify([{"key": k, "name": n, "description": d} for k, n, _, d in SCANNERS])


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

    target_name = os.path.basename(scan_state["results"].get("target", "project"))
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
