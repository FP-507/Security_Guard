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

from core.pdf_generator import generate_pdf
from core.scoring import calculate_score, get_grade
from scanners.base import Severity, ScanResult, Finding
from scanners.registry import SCANNERS, by_key, code_scanners, web_scanners
from core import github_fetcher

app = Flask(__name__)

# Scanner metadata is owned by ``scanners.registry`` (single source of truth
# shared with the CLI). These names are kept as locals for backwards
# compatibility with anything that imports them.
ALL_SCANNERS = SCANNERS
CODE_SCANNERS = code_scanners()
WEB_SCANNERS = web_scanners()

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
# Score & grade come from core.scoring (single source of truth) — see imports.

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


# ── Scan worker ───────────────────────────────────────────────────────────────
def _execute_scan(
    display_target: str,
    scan_path: str,
    scanner_keys: list[str],
    scan_type: str,
) -> None:
    """Run the selected scanners and write results into ``scan_state``.

    Pure scan loop — does **not** touch ``scan_state["running"]`` or perform
    any cleanup. Intended to be called from a wrapper that owns the lifecycle
    (see :func:`run_scan_thread` / :func:`run_github_scan_thread`).
    """
    registry = by_key()
    selected = [registry[k] for k in scanner_keys if k in registry]

    all_findings: list[dict] = []
    scanner_results: list[dict] = []
    total = len(selected) or 1  # avoid div-by-zero on empty selection

    for idx, entry in enumerate(selected):
        key, name, cls, desc = entry.key, entry.name, entry.cls, entry.description
        scan_state["current_scanner"] = name
        scan_state["progress"] = int((idx / total) * 100)

        try:
            scanner = cls(scan_path)
            result = scanner.scan()
        except Exception as scanner_err:
            # One scanner crashing must not abort the whole pipeline.
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

    # Score & grade come from core.scoring — same numbers as the CLI / PDF.
    score = calculate_score(all_findings)
    grade = get_grade(score)

    severity_counts = Counter(f["severity"] for f in all_findings)
    category_counts = Counter(f["category"] for f in all_findings)
    # Most severe first — drives the order shown in the dashboard.
    all_findings.sort(key=lambda f: f["severity_score"], reverse=True)

    scan_state["results"] = {
        "target": display_target,
        "scan_type": scan_type,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "score": score,
        "grade": grade,
        "total_findings": len(all_findings),
        "severity_counts": {sev: severity_counts.get(sev, 0)
                             for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
        "category_counts": dict(category_counts.most_common()),
        "scanners": scanner_results,
        "findings": all_findings,
    }
    scan_state["progress"] = 100
    scan_state["current_scanner"] = "Complete"


def _reset_state(scan_type: str) -> None:
    """Initialize ``scan_state`` for a new scan run."""
    scan_state["running"] = True
    scan_state["progress"] = 0
    scan_state["error"] = None
    scan_state["results"] = None
    scan_state["scan_type"] = scan_type


def run_scan_thread(
    display_target: str,
    scan_path: str,
    scanner_keys: list[str],
    scan_type: str = "local",
    tmp_dir: str = None,
):
    """Local-path / website worker: own state lifecycle, then delegate scan loop."""
    _reset_state(scan_type)
    try:
        _execute_scan(display_target, scan_path, scanner_keys, scan_type)
    except Exception as e:
        scan_state["error"] = str(e)
    finally:
        if tmp_dir:
            github_fetcher.cleanup_temp_dir(tmp_dir)
        scan_state["running"] = False


def run_github_scan_thread(url: str, scanner_keys: list[str], token: str = None):
    """GitHub worker: clone first (with private-repo detection), then scan."""
    _reset_state("github")
    tmp_dir = None
    try:
        info = github_fetcher.parse_github_url(url)
        display_target = info["display"]

        # Forward git/clone progress messages into the same state slot the
        # scan loop will later update with scanner names.
        def on_progress(msg: str):
            scan_state["current_scanner"] = msg

        scan_state["current_scanner"] = "Cloning repository..."
        tmp_dir = github_fetcher.clone_repo(url, token=token, progress_callback=on_progress)

        _execute_scan(display_target, tmp_dir, scanner_keys, "github")
    except Exception as e:
        scan_state["error"] = str(e)
    finally:
        if tmp_dir:
            github_fetcher.cleanup_temp_dir(tmp_dir)
        scan_state["running"] = False


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
        {"key": s.key, "name": s.name, "description": s.description}
        for s in CODE_SCANNERS
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
