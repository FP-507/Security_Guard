# 🛡️ Security Guard

> **Automated multi-layer security auditing for developers, by a developer.**
> Scan any codebase, GitHub repository, or live website and get a prioritized,
> actionable security report — in seconds.

---

## What is Security Guard?

Security Guard is a **DevSecOps-grade security analysis tool** that combines
static analysis, secret detection, dependency auditing, and live web scanning
into one unified interface. It speaks the same language as professional tools
used at enterprise level — OWASP Top 10 categories, CWE identifiers, attack
simulations — but runs with a single command on your local machine.

Whether you're auditing your own project before deployment, reviewing a
colleague's pull request, or evaluating a third-party repository, Security Guard
gives you the context you need: not just *what* the problem is, but *why* it
exists and *what happens* if an attacker exploits it.

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Static Code Analysis** | 25+ vulnerability patterns — SQL injection, XSS, SSTI, path traversal, weak crypto, and more |
| 🔑 **Secret Detection** | 30+ regex patterns + Shannon entropy analysis to find leaked API keys, tokens, and passwords |
| 📦 **Dependency Scanning** | Checks Python, Node.js, Ruby, and Go dependencies against 51 known CVEs with semver parsing |
| ⚙️ **Config Auditing** | Reviews Docker, CI/CD pipelines, SSL config, cookies, and CORS policies |
| 🛡️ **Insecure Defaults** | Detects fail-open patterns (Trail of Bits methodology): fallback secrets, disabled-by-default auth, weak crypto in context |
| ⚔️ **Attack Simulation** | 20 context-aware attack vectors — shows exactly how an attacker would exploit each finding |
| 🌐 **Live Web Auditing** | Black-box scanning of live websites: security headers, cookies, XSS, open redirect, CORS, and more |
| 🐙 **GitHub Integration** | Paste any GitHub repo URL — Security Guard clones and scans it automatically |
| 📄 **PDF Export** | Professional bilingual (ES/EN) PDF reports with score ring, findings, attack simulations, and remediation roadmap |

---

## Security Score

Every scan produces a **0–100 security score** with letter grade:

| Score | Grade | Meaning |
|---|---|---|
| 90–100 | **A** | Production-ready, minimal risk |
| 80–89 | **B** | Minor issues, monitor closely |
| 70–79 | **C** | Needs improvement before production |
| 60–69 | **D** | Significant vulnerabilities present |
| 0–59 | **F** | Not suitable for production |

Each finding deducts points based on severity: Critical (−15), High (−8),
Medium (−4), Low (−2), Info (−0.5).

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-username/security-guard.git
cd security-guard
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> **Requires Python 3.10+** and `git` installed and available in PATH.

### 3. Start the web interface

```bash
python run.py
```

Open your browser at **http://localhost:5000**

---

## Usage

### Web Interface (recommended)

After running `python run.py`, the dashboard lets you:

- **📁 Local Path** — scan any directory on your machine
- **🐙 GitHub Repo** — paste a GitHub URL (public or private with token)
- **🌐 Website** — paste any `https://` URL for live black-box auditing

Results appear in real time with a progress bar. When the scan completes you
can filter findings by severity, search by keyword, and download a PDF report
in Spanish or English.

### CLI (alternative)

```bash
# Scan a local project and print to console
python security_guard.py /path/to/your/project

# Generate an HTML report
python security_guard.py /path/to/project --html

# Run only specific scanners
python security_guard.py /path/to/project --scanners static,secrets,deps

# Filter by minimum severity
python security_guard.py /path/to/project --severity high
```

### API (programmatic)

```bash
# Start a scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/project"}'

# Scan a GitHub repo
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "https://github.com/owner/repo"}'

# Scan a live website
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "https://example.com"}'

# Poll for status
curl http://localhost:5000/api/status

# Get results (JSON)
curl http://localhost:5000/api/results

# Download PDF in Spanish
curl http://localhost:5000/api/export/pdf?lang=es -o report.pdf
```

---

## Project Structure

```
security-guard/
│
├── app.py                  # Flask web server (entry point)
├── run.py                  # Production launcher (bypasses bytecode cache)
├── security_guard.py       # CLI entry point
├── requirements.txt        # Python dependencies
│
├── core/                   # Core utility modules
│   ├── github_fetcher.py   # GitHub URL parsing and repo cloning
│   ├── pdf_generator.py    # Bilingual PDF report generation (ReportLab)
│   └── report_generator.py # Console and HTML report generation
│
├── scanners/               # Plug-and-play scanner modules
│   ├── base.py             # BaseScanner, Finding, ScanResult, Severity, Category
│   ├── static_analyzer.py  # Static code vulnerability patterns
│   ├── secret_detector.py  # Secret and high-entropy string detection
│   ├── dependency_scanner.py # CVE matching for Python/JS/Ruby/Go
│   ├── config_auditor.py   # Docker, CI/CD, SSL, and server config auditing
│   ├── insecure_defaults.py # Trail of Bits fail-open pattern detection
│   ├── attack_simulator.py  # Attack vector simulation
│   └── web_auditor.py      # Black-box live web security scanner
│
└── templates/
    └── index.html          # Dark-theme web dashboard
```

---

## Adding a New Scanner

Security Guard is designed to be **Plug & Play**. Every scanner extends the
same `BaseScanner` class:

```python
from scanners.base import BaseScanner, Finding, ScanResult, Severity, Category

class MyCustomScanner(BaseScanner):
    name = "My Custom Scanner"

    def scan(self) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        # Your scanning logic here
        result.findings.append(Finding(
            title="Example Vulnerability",
            severity=Severity.HIGH,
            category=Category.INJECTION,
            file_path="path/to/file.py",
            line_number=42,
            code_snippet="dangerous_code(user_input)",
            description="Why this is dangerous.",
            root_cause="The root cause of the vulnerability.",
            consequences="What an attacker can achieve.",
            recommendation="How to fix it.",
            cwe_id="CWE-89",
            attack_simulation="Proof-of-concept attack payload.",
        ))
        return result
```

Then register it in `app.py`:

```python
from scanners.my_custom_scanner import MyCustomScanner

CODE_SCANNERS = [
    ...
    ("custom", "My Custom Scanner", MyCustomScanner, "Description shown in UI"),
]
```

No other files need to change. The scanner automatically appears in the
dashboard toggles and runs as part of the scan pipeline.

---

## Scanners Detail

### Static Code Analyzer
Detects 25+ vulnerability patterns using context-aware regex with `re.VERBOSE`
precision. Each finding includes the OWASP Top 10 category, a CWE identifier,
the root cause, projected consequences, and a concrete attack simulation.

### Secret Detector
Combines 30+ regex patterns (AWS keys, JWT tokens, private keys, database
connection strings, etc.) with Shannon entropy analysis to catch secrets that
pattern matching alone would miss.

### Dependency Scanner
Parses `requirements.txt`, `package.json`, `Gemfile`, and `go.mod` files and
checks declared versions against a curated database of 51 CVEs using proper
semantic versioning range comparison.

### Config Auditor
Reviews configuration files for common misconfigurations: exposed Docker daemon
sockets, missing security headers in Nginx/Apache, disabled TLS verification,
world-readable files, and CI/CD pipeline injection risks.

### Insecure Defaults (Trail of Bits)
Implements the [Trail of Bits insecure-defaults methodology](https://github.com/trailofbits/not-so-smart-contracts):
detects fail-open patterns where a missing environment variable causes the
application to fall back to an insecure state.

### Attack Simulator
Goes beyond detection — for each of 20 vulnerability categories, it generates
a concrete proof-of-concept payload showing exactly how an attacker would
exploit the vulnerability. Supply chain checks (npm lifecycle scripts, PyPI
typosquatting) are also included.

### Web Auditor
Black-box scanner for live websites. Checks:
- TLS / HTTPS enforcement
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Cookie flags (HttpOnly, Secure, SameSite)
- Sensitive file exposure (`.env`, `.git/config`, `wp-config.php`, and 30+ more)
- CORS misconfiguration
- JavaScript secret leakage
- XSS reflection and open redirect
- Technology fingerprinting
- `robots.txt` endpoint disclosure

---

## Security & Privacy

- Security Guard **never sends your code or results to any external server**.
  All analysis runs locally.
- GitHub clones are downloaded to a temporary directory and deleted automatically
  when the scan completes.
- Reports may contain sensitive findings — treat exported PDFs as confidential
  and do not commit them to version control (they are excluded by `.gitignore`).

---

## License

MIT License. See `LICENSE` for details.

---

*Built with Python, Flask, ReportLab, and a commitment to making security
accessible to every developer.*
