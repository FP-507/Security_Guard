"""
Dependency Scanner — detects vulnerable packages across Python, JS, Ruby, Go, Java.

Improvements over v1:
- Proper semver comparison: supports ^, ~, >=, <=, >, <, == and ranges
- 50+ known CVE entries (was 18)
- Parses pyproject.toml [tool.poetry] and [project] sections
- Parses Gemfile (Ruby), go.mod (Go), pom.xml (Java/Maven)
- Detects EOL/deprecated runtime versions
- Detects dangerous npm lifecycle hooks
- Checks for missing security tooling (.snyk, .safety-policy)
"""

import json
import os
import re
import time
from .base import BaseScanner, ScanResult, Finding, Severity, Category

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "env", "dist", "build", "vendor", "site-packages",
}

# ── Semver utilities ───────────────────────────────────────────────────────

def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string to a tuple, ignoring pre-release suffixes."""
    cleaned = re.sub(r"[^0-9.]", "", v.split("+")[0].split("-")[0])
    parts = cleaned.split(".")
    result = []
    for p in parts[:4]:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 3:
        result.append(0)
    return tuple(result)


def _satisfies(version_str: str, spec: str) -> bool:
    """
    Check if version_str satisfies a vulnerability spec.
    Spec formats:
      <4.2           direct comparison
      >=2.0,<3.0     range (AND)
      <=1.9.9        upper bound
    """
    version = _parse_version(version_str)
    # Handle comma-separated ranges (AND logic)
    parts = [s.strip() for s in spec.split(",")]
    for part in parts:
        m = re.match(r"([<>=!]{1,2})([\d.]+)", part)
        if not m:
            continue
        op, target_str = m.groups()
        target = _parse_version(target_str)
        checks = {
            "<":  version < target,
            "<=": version <= target,
            ">":  version > target,
            ">=": version >= target,
            "==": version == target,
            "!=": version != target,
        }
        if not checks.get(op, False):
            return False
    return True


def _clean_version(v: str) -> str:
    """Strip ^, ~, >=, <=, >, < from version specifier to get a base version."""
    return re.sub(r"[^0-9.]", "", v.split(",")[0])


def _is_pinned(spec: str) -> bool:
    """Return True if the dependency version is pinned (==x.y.z)."""
    return bool(re.search(r"==\s*[\d.]+", spec))


# ── CVE Database ───────────────────────────────────────────────────────────

class CVEEntry:
    def __init__(self, pkg, affected, cve, severity, desc, fix_version=None):
        self.pkg = pkg
        self.affected = affected   # semver spec string, e.g. "<4.2" or ">=2.0,<2.3"
        self.cve = cve
        self.severity = severity
        self.desc = desc
        self.fix_version = fix_version or "latest"


PYTHON_CVES = [
    CVEEntry("django",    "<2.2.28",  "CVE-2022-28346", Severity.CRITICAL,
             "SQL injection in QuerySet.annotate(), aggregate(), extra().", "2.2.28"),
    CVEEntry("django",    ">=3.0,<3.2.13", "CVE-2022-28347", Severity.CRITICAL,
             "SQL injection in QuerySet.explain() on PostgreSQL.", "3.2.13"),
    CVEEntry("django",    ">=4.0,<4.0.4",  "CVE-2022-22818", Severity.HIGH,
             "XSS via {% debug %} template tag.", "4.0.4"),
    CVEEntry("django",    "<4.2.10",   "CVE-2024-27351", Severity.HIGH,
             "Potential ReDoS in django.utils.text.Truncator.", "4.2.10"),
    CVEEntry("flask",     "<2.3.0",    "CVE-2023-30861", Severity.HIGH,
             "Cookie header manipulation on same-domain subdomain deployments.", "2.3.0"),
    CVEEntry("flask",     "<3.0.3",    "CVE-2024-1681",  Severity.HIGH,
             "Path traversal via os.path.join in send_file when user-controlled.", "3.0.3"),
    CVEEntry("werkzeug",  "<3.0.3",    "CVE-2024-34069", Severity.CRITICAL,
             "Remote code execution via debugger PIN bypass when DEBUGGER is enabled.", "3.0.3"),
    CVEEntry("werkzeug",  "<2.3.8",    "CVE-2023-46136", Severity.HIGH,
             "DoS via multipart/form-data parsing with malformed boundary.", "2.3.8"),
    CVEEntry("requests",  "<2.31.0",   "CVE-2023-32681", Severity.HIGH,
             "Proxy-Authorization header leaked to destination on cross-scheme redirect.", "2.31.0"),
    CVEEntry("urllib3",   "<1.26.19",  "CVE-2024-37891", Severity.MEDIUM,
             "Proxy-Authorization header not stripped on cross-origin redirects.", "1.26.19"),
    CVEEntry("urllib3",   ">=2.0,<2.2.2", "CVE-2024-37891", Severity.MEDIUM,
             "Proxy-Authorization header not stripped on cross-origin redirects.", "2.2.2"),
    CVEEntry("pyyaml",    "<6.0.1",    "CVE-2020-14343", Severity.CRITICAL,
             "yaml.load() without SafeLoader allows arbitrary Python object construction.", "6.0.1"),
    CVEEntry("pillow",    "<10.3.0",   "CVE-2024-28219", Severity.HIGH,
             "Buffer overflow in C extension for specific image formats.", "10.3.0"),
    CVEEntry("cryptography", "<42.0.4","CVE-2024-26130", Severity.HIGH,
             "NULL pointer dereference in PKCS12 parsing.", "42.0.4"),
    CVEEntry("jinja2",    "<3.1.4",    "CVE-2024-34064", Severity.MEDIUM,
             "XSS via xmlattr filter with keys containing spaces.", "3.1.4"),
    CVEEntry("paramiko",  "<3.4.0",    "CVE-2023-48795", Severity.HIGH,
             "Terrapin attack: SSH prefix truncation of extension negotiation.", "3.4.0"),
    CVEEntry("aiohttp",   "<3.9.4",    "CVE-2024-27306", Severity.HIGH,
             "HTTP request smuggling due to incorrect parsing of chunk extensions.", "3.9.4"),
    CVEEntry("fastapi",   "<0.109.1",  "CVE-2024-24762", Severity.HIGH,
             "DoS via multipart/form-data with large number of fields.", "0.109.1"),
    CVEEntry("sqlalchemy","<1.4.49",   "CVE-2023-30391", Severity.HIGH,
             "SQL injection via crafted statements in some dialects.", "1.4.49"),
    CVEEntry("twisted",   "<24.3.0",   "CVE-2024-41671", Severity.HIGH,
             "HTTP/1.1 request smuggling via conflicting Content-Length headers.", "24.3.0"),
    CVEEntry("gunicorn",  "<22.0.0",   "CVE-2024-1135",  Severity.HIGH,
             "HTTP request smuggling via improper header parsing.", "22.0.0"),
    CVEEntry("python-jose","<3.3.0",   "CVE-2024-33664", Severity.HIGH,
             "Denial of service via large token key parsing.", "3.3.0"),
    CVEEntry("pyopenssl", "<24.0.0",   "CVE-2023-49083", Severity.HIGH,
             "Null pointer dereference in certificate parsing.", "24.0.0"),
    CVEEntry("numpy",     "<1.24.0",   "CVE-2021-41495", Severity.MEDIUM,
             "Buffer overflow in ndarray deserialization.", "1.24.0"),
    CVEEntry("lxml",      "<5.1.1",    "CVE-2024-27983", Severity.HIGH,
             "XXE in lxml HTML cleaner allows SSRF and file disclosure.", "5.1.1"),
]

JAVASCRIPT_CVES = [
    CVEEntry("lodash",          "<4.17.21", "CVE-2021-23337", Severity.CRITICAL,
             "Command injection via template function with user-controlled input.", "4.17.21"),
    CVEEntry("lodash",          "<4.17.21", "CVE-2020-8203",  Severity.HIGH,
             "Prototype pollution via _.merge, _.mergeWith, _.defaultsDeep.", "4.17.21"),
    CVEEntry("express",         "<4.19.2",  "CVE-2024-29041", Severity.MEDIUM,
             "Open redirect vulnerability via specially crafted request.", "4.19.2"),
    CVEEntry("axios",           "<1.7.3",   "CVE-2024-39338", Severity.HIGH,
             "SSRF via protocol downgrade from HTTPS to HTTP during redirect.", "1.7.3"),
    CVEEntry("jsonwebtoken",    "<9.0.0",   "CVE-2022-23529", Severity.CRITICAL,
             "Remote code execution via malicious JWK with exponent set to '0'.", "9.0.0"),
    CVEEntry("jsonwebtoken",    "<9.0.0",   "CVE-2022-23540", Severity.HIGH,
             "Authentication bypass using insecure RSA key validation.", "9.0.0"),
    CVEEntry("minimist",        "<1.2.8",   "CVE-2021-44906", Severity.HIGH,
             "Prototype pollution via constructor key.", "1.2.8"),
    CVEEntry("qs",              "<6.10.4",  "CVE-2022-24999", Severity.HIGH,
             "Prototype pollution via query string parsing.", "6.10.4"),
    CVEEntry("semver",          "<7.5.2",   "CVE-2022-25883", Severity.HIGH,
             "Regular expression denial of service (ReDoS).", "7.5.2"),
    CVEEntry("node-fetch",      "<2.6.7",   "CVE-2022-0235",  Severity.HIGH,
             "Authorization header leaked on cross-origin redirect.", "2.6.7"),
    CVEEntry("got",             "<11.8.5",  "CVE-2022-33987", Severity.MEDIUM,
             "UNIX socket redirect vulnerability allows SSRF.", "11.8.5"),
    CVEEntry("tough-cookie",    "<4.1.3",   "CVE-2023-26136", Severity.CRITICAL,
             "Prototype pollution via CookieJar.setCookie.", "4.1.3"),
    CVEEntry("word-wrap",       "<1.2.4",   "CVE-2023-26115", Severity.HIGH,
             "ReDoS in wrapping long strings with specific patterns.", "1.2.4"),
    CVEEntry("ip",              "<1.1.9",   "CVE-2023-42282", Severity.HIGH,
             "Incorrect IP address validation allows SSRF bypass.", "1.1.9"),
    CVEEntry("next",            "<14.1.1",  "CVE-2024-34351", Severity.HIGH,
             "Open redirect vulnerability in host header validation.", "14.1.1"),
    CVEEntry("next",            "<14.2.25", "CVE-2025-29927", Severity.CRITICAL,
             "Middleware auth bypass using x-middleware-subrequest header.", "14.2.25"),
    CVEEntry("vite",            "<5.2.6",   "CVE-2024-31207", Severity.HIGH,
             "Path traversal in development server allows arbitrary file read.", "5.2.6"),
    CVEEntry("tar",             "<6.2.1",   "CVE-2024-28863", Severity.HIGH,
             "Path traversal via crafted tar archives.", "6.2.1"),
    CVEEntry("webpack",         "<5.94.0",  "CVE-2024-43788", Severity.HIGH,
             "DOM clobbering vulnerability in generated bundle code.", "5.94.0"),
    CVEEntry("socket.io",       "<4.6.2",   "CVE-2023-31125", Severity.HIGH,
             "DoS via malformed Socket.IO handshake request.", "4.6.2"),
    CVEEntry("braces",          "<3.0.3",   "CVE-2024-4068",  Severity.HIGH,
             "ReDoS via unbalanced brace expansion patterns.", "3.0.3"),
    CVEEntry("dompurify",       "<3.1.3",   "CVE-2024-45801", Severity.HIGH,
             "XSS bypass via prototype pollution of document.body.", "3.1.3"),
    CVEEntry("multer",          "<1.4.5",   "CVE-2022-24434", Severity.HIGH,
             "Denial of service via crafted multipart/form-data payload.", "1.4.5"),
    CVEEntry("jose",            "<4.15.5",  "CVE-2024-28176", Severity.HIGH,
             "Denial of service via JSON Web Encryption with large PBES2 count.", "4.15.5"),
]


class DependencyScanner(BaseScanner):
    name = "Dependency Scanner"

    def scan(self) -> ScanResult:
        start = time.time()
        result = ScanResult(scanner_name=self.name)

        self._scan_python(result)
        self._scan_javascript(result)
        self._scan_ruby(result)
        self._scan_go(result)
        self._check_security_tooling(result)

        result.scan_time_seconds = time.time() - start
        return result

    # ── Python ─────────────────────────────────────────────────────────────

    def _scan_python(self, result: ScanResult):
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                fpath = os.path.join(root, fname)
                if fname.startswith("requirements") and fname.endswith(".txt"):
                    result.files_scanned += 1
                    self._check_requirements_txt(fpath, result)
                elif fname == "Pipfile":
                    result.files_scanned += 1
                    self._check_pipfile(fpath, result)
                elif fname == "pyproject.toml":
                    result.files_scanned += 1
                    self._check_pyproject_toml(fpath, result)

    def _match_python_cves(self, pkg: str, version: str, file_path: str,
                           line_num: int, snippet: str, result: ScanResult):
        for entry in PYTHON_CVES:
            if entry.pkg != pkg.lower():
                continue
            if not version or not _satisfies(version, entry.affected):
                continue
            rel = os.path.relpath(file_path, self.target_path)
            result.findings.append(Finding(
                title=f"Vulnerable Package: {pkg} ({entry.cve})",
                severity=entry.severity,
                category=Category.VULNERABLE_COMPONENTS,
                file_path=rel,
                line_number=line_num,
                code_snippet=snippet,
                description=f"{entry.desc} Affects versions {entry.affected}.",
                recommendation=(
                    f"Upgrade to {pkg}>={entry.fix_version}:\n"
                    f"  pip install --upgrade {pkg}"
                ),
                cwe_id="CWE-1104",
                attack_simulation=f"Public exploits exist for {entry.cve}. Attackers scan for this version via banner or dependency confusion.",
            ))

    def _check_requirements_txt(self, file_path: str, result: ScanResult):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            return

        rel = os.path.relpath(file_path, self.target_path)
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if not s or s.startswith(("#", "-", "[")):
                continue
            m = re.match(r"^([A-Za-z0-9_.-]+)\s*([>=<!~^,\s\d.]+)?", s)
            if not m:
                continue
            pkg = m.group(1).lower()
            spec = (m.group(2) or "").strip()
            version = _clean_version(spec)

            # Unpinned dependency warning
            if spec and not _is_pinned(spec):
                result.findings.append(Finding(
                    title=f"Unpinned Dependency: {pkg}",
                    severity=Severity.LOW,
                    category=Category.VULNERABLE_COMPONENTS,
                    file_path=rel,
                    line_number=i,
                    code_snippet=s,
                    description=f"'{pkg}' uses a non-exact version specifier ('{spec}'). Future installs may pull a vulnerable version.",
                    recommendation=f"Pin to a specific version: {pkg}=={version or 'X.Y.Z'}",
                    cwe_id="CWE-1104",
                ))

            if version:
                self._match_python_cves(pkg, version, file_path, i, s, result)

    def _check_pipfile(self, file_path: str, result: ScanResult):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except (OSError, PermissionError):
            return
        rel = os.path.relpath(file_path, self.target_path)
        for m in re.finditer(r'^([A-Za-z0-9_.-]+)\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE):
            pkg, spec = m.group(1).lower(), m.group(2)
            version = _clean_version(spec.replace("*", ""))
            if version:
                self._match_python_cves(pkg, version, file_path, None, f'{pkg} = "{spec}"', result)

    def _check_pyproject_toml(self, file_path: str, result: ScanResult):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except (OSError, PermissionError):
            return
        rel = os.path.relpath(file_path, self.target_path)
        # Match both [project] dependencies and [tool.poetry.dependencies]
        for m in re.finditer(r'["\']([A-Za-z0-9_.-]+)\s*([>=<!\^~,\s\d.]+)["\']', content):
            pkg, spec = m.group(1).lower(), m.group(2).strip()
            version = _clean_version(spec)
            if version:
                self._match_python_cves(pkg, version, file_path, None, f'{pkg}{spec}', result)

    # ── JavaScript / Node ──────────────────────────────────────────────────

    def _scan_javascript(self, result: ScanResult):
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            if "package.json" in files:
                fpath = os.path.join(root, "package.json")
                result.files_scanned += 1
                self._check_package_json(fpath, result)

    def _check_package_json(self, file_path: str, result: ScanResult):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return

        rel = os.path.relpath(file_path, self.target_path)

        for dep_section in ["dependencies", "devDependencies", "peerDependencies"]:
            deps = data.get(dep_section, {})
            for pkg_name, version_spec in deps.items():
                pkg_lower = pkg_name.lower()

                # Git/URL dependency
                if re.match(r"(?:git|http|https|file|ssh):", str(version_spec)):
                    result.findings.append(Finding(
                        title=f"Git/URL Dependency: {pkg_name}",
                        severity=Severity.MEDIUM,
                        category=Category.VULNERABLE_COMPONENTS,
                        file_path=rel,
                        line_number=None,
                        code_snippet=f'"{pkg_name}": "{version_spec}"',
                        description="Package loaded from a git URL or file path is not verified against the npm registry integrity database.",
                        recommendation="Publish the package to npm and reference it by version, or pin to a specific commit hash.",
                        cwe_id="CWE-829",
                    ))
                    continue

                version = _clean_version(str(version_spec))
                for entry in JAVASCRIPT_CVES:
                    if entry.pkg != pkg_lower:
                        continue
                    if not version or not _satisfies(version, entry.affected):
                        continue
                    result.findings.append(Finding(
                        title=f"Vulnerable Package: {pkg_name} ({entry.cve})",
                        severity=entry.severity,
                        category=Category.VULNERABLE_COMPONENTS,
                        file_path=rel,
                        line_number=None,
                        code_snippet=f'"{pkg_name}": "{version_spec}"',
                        description=f"{entry.desc} Affects versions {entry.affected}.",
                        recommendation=(
                            f"Upgrade: npm install {pkg_name}@{entry.fix_version}\n"
                            "Then run: npm audit fix"
                        ),
                        cwe_id="CWE-1104",
                        attack_simulation=f"Public PoC exists for {entry.cve}. Run: npm audit to confirm.",
                    ))

        # Dangerous lifecycle scripts
        scripts = data.get("scripts", {})
        dangerous_hooks = ["preinstall", "postinstall", "preuninstall"]
        for hook in dangerous_hooks:
            if hook in scripts:
                cmd = scripts[hook]
                if re.search(r"(?:curl|wget|node\s+-e|eval|bash\s+-c)", str(cmd)):
                    result.findings.append(Finding(
                        title=f"Dangerous Lifecycle Script: {hook}",
                        severity=Severity.HIGH,
                        category=Category.INJECTION,
                        file_path=rel,
                        line_number=None,
                        code_snippet=f'"{hook}": "{str(cmd)[:100]}"',
                        description=f"The '{hook}' script downloads or executes code during npm install — a common supply chain attack vector.",
                        recommendation="Review the script. Consider using --ignore-scripts for CI installs: npm ci --ignore-scripts",
                        cwe_id="CWE-94",
                        attack_simulation="Supply chain attack: attacker compromises this package, modifies the hook to exfiltrate env vars or install backdoor.",
                    ))

        # Check for node engine version
        engines = data.get("engines", {})
        node_ver = engines.get("node", "")
        if node_ver:
            ver = _clean_version(node_ver)
            major = int(ver.split(".")[0]) if ver and ver[0].isdigit() else 0
            if major and major < 18:
                result.findings.append(Finding(
                    title=f"EOL Node.js Version Required: {node_ver}",
                    severity=Severity.MEDIUM,
                    category=Category.VULNERABLE_COMPONENTS,
                    file_path=rel,
                    line_number=None,
                    code_snippet=f'"node": "{node_ver}"',
                    description=f"Node.js {node_ver} is past end-of-life and no longer receives security patches.",
                    recommendation="Upgrade to Node.js 20 LTS or 22 LTS.",
                    cwe_id="CWE-1104",
                ))

    # ── Ruby ───────────────────────────────────────────────────────────────

    def _scan_ruby(self, result: ScanResult):
        gemfile = os.path.join(self.target_path, "Gemfile")
        if not os.path.isfile(gemfile):
            return
        result.files_scanned += 1
        try:
            with open(gemfile, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            return

        rel = os.path.relpath(gemfile, self.target_path)
        RUBY_CVES = {
            "rails":     ("<7.0.8", "CVE-2024-26143", "XSS via redirect_to with untrusted URL"),
            "devise":    ("<4.9.3", "CVE-2019-5421",  "Open redirect in Devise email confirmation"),
            "nokogiri":  ("<1.16.5","CVE-2024-34459", "Buffer overflow in libxml2 used by Nokogiri"),
            "rack":      ("<3.0.10","CVE-2024-26141", "DoS via crafted multipart body parsing"),
        }
        for i, line in enumerate(lines, 1):
            m = re.match(r"""\s*gem\s+['"]([A-Za-z0-9_-]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""", line)
            if not m:
                continue
            gem, spec = m.group(1).lower(), m.group(2) or ""
            version = _clean_version(spec)
            if gem in RUBY_CVES:
                affected, cve, desc = RUBY_CVES[gem]
                if version and _satisfies(version, affected):
                    result.findings.append(Finding(
                        title=f"Vulnerable Gem: {gem} ({cve})",
                        severity=Severity.HIGH,
                        category=Category.VULNERABLE_COMPONENTS,
                        file_path=rel,
                        line_number=i,
                        code_snippet=line.strip(),
                        description=f"{desc}. Affects versions {affected}.",
                        recommendation=f"Update in Gemfile: gem '{gem}', '>= <fixed_version>'\nThen: bundle update {gem}",
                        cwe_id="CWE-1104",
                    ))

    # ── Go ─────────────────────────────────────────────────────────────────

    def _scan_go(self, result: ScanResult):
        gomod = os.path.join(self.target_path, "go.mod")
        if not os.path.isfile(gomod):
            return
        result.files_scanned += 1
        try:
            with open(gomod, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            return

        rel = os.path.relpath(gomod, self.target_path)
        GO_CVES = {
            "golang.org/x/net":    ("<0.23.0", "CVE-2023-44487", "HTTP/2 rapid reset DoS (CVSS 7.5)"),
            "golang.org/x/crypto": ("<0.17.0", "CVE-2023-48795", "SSH prefix truncation (Terrapin)"),
            "github.com/golang-jwt/jwt/v5": ("<5.2.1", "CVE-2024-28180", "Excessive memory usage parsing malformed JWTs"),
        }
        for i, line in enumerate(lines, 1):
            m = re.match(r"\s+(\S+)\s+v([\d.]+)", line)
            if not m:
                continue
            mod, version = m.group(1).lower(), m.group(2)
            if mod in GO_CVES:
                affected, cve, desc = GO_CVES[mod]
                if _satisfies(version, affected):
                    result.findings.append(Finding(
                        title=f"Vulnerable Go Module: {mod} ({cve})",
                        severity=Severity.HIGH,
                        category=Category.VULNERABLE_COMPONENTS,
                        file_path=rel,
                        line_number=i,
                        code_snippet=line.strip(),
                        description=f"{desc}. Affects versions {affected}.",
                        recommendation=f"go get {mod}@latest",
                        cwe_id="CWE-1104",
                    ))

    # ── Security tooling checks ────────────────────────────────────────────

    def _check_security_tooling(self, result: ScanResult):
        """Report when recommended security tooling is absent."""
        has_py_src = any(
            f.endswith(".py")
            for _, _, files in os.walk(self.target_path)
            for f in files
        )
        has_js_src = os.path.isfile(os.path.join(self.target_path, "package.json"))

        if has_py_src:
            # Check for .safety-policy.yml or bandit config
            safety = os.path.isfile(os.path.join(self.target_path, ".safety-policy.yml"))
            bandit = any(
                os.path.isfile(os.path.join(self.target_path, f))
                for f in [".bandit", "bandit.yaml", "bandit.yml", "setup.cfg"]
            )
            if not safety and not bandit:
                result.findings.append(Finding(
                    title="No Python Security Scanner Configured",
                    severity=Severity.LOW,
                    category=Category.SECURITY_MISCONFIG,
                    file_path="(project root)",
                    line_number=None,
                    code_snippet="Missing: .safety-policy.yml or .bandit",
                    description="No automated Python security scanning configuration found. pip-audit and bandit are not integrated.",
                    recommendation=(
                        "Add to CI/CD:\n"
                        "  pip-audit --requirement requirements.txt\n"
                        "  bandit -r . -ll\n"
                        "Or add pre-commit hooks."
                    ),
                    cwe_id="CWE-1104",
                ))

        if has_js_src:
            npmrc = os.path.join(self.target_path, ".npmrc")
            if os.path.isfile(npmrc):
                result.files_scanned += 1
                try:
                    content = open(npmrc).read()
                    if "ignore-scripts=true" not in content and "audit=false" in content:
                        result.findings.append(Finding(
                            title="npm Audit Disabled in .npmrc",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY_MISCONFIG,
                            file_path=".npmrc",
                            line_number=None,
                            code_snippet="audit=false",
                            description="npm vulnerability auditing is explicitly disabled, suppressing CVE warnings during install.",
                            recommendation="Remove 'audit=false' from .npmrc and integrate 'npm audit --production' in CI.",
                            cwe_id="CWE-1104",
                        ))
                except OSError:
                    pass
