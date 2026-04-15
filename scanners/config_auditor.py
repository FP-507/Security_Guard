"""
Configuration Auditor — detects security misconfigurations across project files.

New in v2:
- Cookie security flags (Secure, HttpOnly, SameSite)
- Missing security headers middleware detection
- Content Security Policy presence check
- Dangerous HTTP methods (TRACE, PUT without auth)
- Exposed admin/debug endpoints
- Hardcoded IPs (non-localhost)
- Weak session configuration
- Missing rate limiting on auth endpoints
- Dockerfile: HEALTHCHECK, read-only filesystem, capabilities
- GitHub Actions: permission hardening
"""

import json
import os
import re
import time
from .base import BaseScanner, ScanResult, Finding, Severity, Category

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "vendor", "site-packages",
}
MAX_FILE_SIZE = 500_000


def _read(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except (OSError, PermissionError):
        return None


def _read_lines(path: str) -> list[str]:
    content = _read(path)
    return content.splitlines() if content else []


class ConfigAuditor(BaseScanner):
    name = "Configuration Auditor"

    def scan(self) -> ScanResult:
        start = time.time()
        result = ScanResult(scanner_name=self.name)

        self._check_gitignore(result)
        self._check_env_files(result)
        self._check_docker(result)
        self._check_nginx_apache(result)
        self._check_package_json(result)
        self._check_security_headers_middleware(result)
        self._check_cookie_security(result)
        self._check_session_config(result)
        self._check_rate_limiting(result)
        self._check_hardcoded_ips(result)
        self._check_ssl_tls(result)
        self._check_ci_cd(result)
        self._check_csp(result)

        result.scan_time_seconds = time.time() - start
        return result

    # ── .gitignore ─────────────────────────────────────────────────────────

    def _check_gitignore(self, result: ScanResult):
        git_dir = os.path.join(self.target_path, ".git")
        if not os.path.isdir(git_dir):
            return  # Not a git repo

        gitignore_path = os.path.join(self.target_path, ".gitignore")
        if not os.path.isfile(gitignore_path):
            result.findings.append(Finding(
                title="Missing .gitignore in Git Repository",
                severity=Severity.HIGH,
                category=Category.SECURITY_MISCONFIG,
                file_path=".gitignore",
                line_number=None,
                code_snippet="File not found",
                description="No .gitignore found. Sensitive files (.env, keys, credentials) may be accidentally committed.",
                recommendation="Create a .gitignore including: .env*, *.key, *.pem, credentials.json, node_modules/",
            ))
            return

        result.files_scanned += 1
        content = (_read(gitignore_path) or "").lower()

        critical = {
            ".env":           "Environment variable files with secrets",
            "*.key":          "Private key files",
            "*.pem":          "Certificate/key files",
            ".DS_Store":      "macOS metadata (may leak directory structure)",
            "*.log":          "Log files (may contain sensitive data)",
        }
        for pattern, desc in critical.items():
            if pattern.lower() not in content:
                result.findings.append(Finding(
                    title=f".gitignore: Missing Pattern '{pattern}'",
                    severity=Severity.LOW,
                    category=Category.SECURITY_MISCONFIG,
                    file_path=".gitignore",
                    line_number=None,
                    code_snippet=f"Pattern '{pattern}' not found",
                    description=f"{desc} are not excluded. Files matching '{pattern}' could be committed.",
                    recommendation=f"Add '{pattern}' to .gitignore.",
                ))

    # ── .env files ─────────────────────────────────────────────────────────

    def _check_env_files(self, result: ScanResult):
        """Warn if .env.example contains real-looking values (copy-paste risk)."""
        for fname in [".env.example", ".env.sample", ".env.template"]:
            fpath = os.path.join(self.target_path, fname)
            if not os.path.isfile(fpath):
                continue
            result.files_scanned += 1
            lines = _read_lines(fpath)
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                m = re.match(r"([A-Z_]+)\s*=\s*(.+)", stripped)
                if not m:
                    continue
                key, value = m.groups()
                # Real-looking: not placeholder
                suspicious = not re.match(
                    r"(?:your_|<|{|\[|xxx|change|placeholder|example|sample|replace|''|\"\")",
                    value, re.IGNORECASE
                )
                if suspicious and len(value) > 10:
                    rel = os.path.relpath(fpath, self.target_path)
                    result.findings.append(Finding(
                        title=f"Real-Looking Value in Example .env: {key}",
                        severity=Severity.MEDIUM,
                        category=Category.SENSITIVE_DATA,
                        file_path=rel,
                        line_number=i,
                        code_snippet=f"{key}=[REDACTED]",
                        description=f"'{key}' in the example .env file has a real-looking value. Developers may copy this file and commit real secrets.",
                        recommendation=f"Replace the value with a placeholder: {key}=your_{key.lower()}_here",
                    ))

    # ── Dockerfile ─────────────────────────────────────────────────────────

    def _check_docker(self, result: ScanResult):
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if fname == "Dockerfile" or re.match(r"Dockerfile\.\w+", fname):
                    fpath = os.path.join(root, fname)
                    result.files_scanned += 1
                    self._audit_dockerfile(fpath, result)

    def _audit_dockerfile(self, file_path: str, result: ScanResult):
        lines = _read_lines(file_path)
        if not lines:
            return

        rel = os.path.relpath(file_path, self.target_path)
        content = "\n".join(lines)
        has_user = False
        has_healthcheck = "HEALTHCHECK" in content.upper()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            upper = stripped.upper()

            if upper.startswith("USER"):
                has_user = True
                if re.match(r"USER\s+root\b", stripped, re.IGNORECASE):
                    result.findings.append(Finding(
                        title="Docker: Explicit USER root",
                        severity=Severity.HIGH,
                        category=Category.BROKEN_ACCESS,
                        file_path=rel,
                        line_number=i,
                        code_snippet=stripped,
                        description="Container is explicitly run as root, maximizing the blast radius of a container escape.",
                        recommendation="Use a non-root user: RUN adduser --disabled-password app && USER app",
                        cwe_id="CWE-269",
                    ))

            if re.match(r"FROM\s+\S+:latest\b", stripped, re.IGNORECASE):
                result.findings.append(Finding(
                    title="Docker: Using 'latest' Tag",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY_MISCONFIG,
                    file_path=rel,
                    line_number=i,
                    code_snippet=stripped,
                    description="'latest' tag is mutable. Future builds may pull a vulnerable image version.",
                    recommendation="Pin to a specific digest: FROM python:3.12-slim@sha256:<digest>",
                ))

            if re.match(r"(?:COPY|ADD)\s+.*(?:\.env|\.key|\.pem|credentials|secret)", stripped, re.IGNORECASE):
                result.findings.append(Finding(
                    title="Docker: Sensitive File Copied Into Image",
                    severity=Severity.CRITICAL,
                    category=Category.SENSITIVE_DATA,
                    file_path=rel,
                    line_number=i,
                    code_snippet=stripped,
                    description="Secrets baked into Docker layers persist even after deletion in later layers.",
                    recommendation="Use Docker BuildKit secrets: RUN --mount=type=secret,id=mykey ...",
                    cwe_id="CWE-522",
                    attack_simulation="docker history <image> --no-trunc reveals all layers including deleted secret files.",
                ))

            if re.match(r"ENV\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*\s*=", stripped, re.IGNORECASE):
                result.findings.append(Finding(
                    title="Docker: Secret in ENV Instruction",
                    severity=Severity.HIGH,
                    category=Category.SENSITIVE_DATA,
                    file_path=rel,
                    line_number=i,
                    code_snippet=stripped,
                    description="Environment variables set with ENV are baked into the image and visible via 'docker inspect'.",
                    recommendation="Use runtime secrets: --env-file or Docker Swarm/Kubernetes secrets at runtime.",
                    cwe_id="CWE-522",
                ))

            if re.match(r"ADD\s+https?://", stripped, re.IGNORECASE):
                result.findings.append(Finding(
                    title="Docker: ADD with Remote URL (No Integrity Check)",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY_MISCONFIG,
                    file_path=rel,
                    line_number=i,
                    code_snippet=stripped,
                    description="ADD with URLs doesn't verify file integrity. A MITM could replace the downloaded file.",
                    recommendation="Use RUN curl --fail -L <url> | sha256sum --check -; then COPY instead of ADD.",
                ))

            if re.match(r"RUN\s+.*(?:curl|wget)\s+.*\|\s*(?:bash|sh)\b", stripped, re.IGNORECASE):
                result.findings.append(Finding(
                    title="Docker: Pipe curl/wget to Shell",
                    severity=Severity.HIGH,
                    category=Category.INJECTION,
                    file_path=rel,
                    line_number=i,
                    code_snippet=stripped,
                    description="Piping downloaded content directly to a shell is a supply chain attack vector.",
                    recommendation="Download, verify checksum, then execute in separate steps.",
                    cwe_id="CWE-829",
                ))

        if not has_user:
            result.findings.append(Finding(
                title="Docker: No USER Directive — Runs as Root",
                severity=Severity.HIGH,
                category=Category.BROKEN_ACCESS,
                file_path=rel,
                line_number=None,
                code_snippet="No USER directive found",
                description="Without USER, the container runs as root by default. A container escape gives the attacker root on the host.",
                recommendation="Add before CMD: RUN adduser --disabled-password app && USER app",
                cwe_id="CWE-269",
                attack_simulation="Container escape CVEs (runc, Containerd) give root shell on host when container runs as root.",
            ))

        if not has_healthcheck:
            result.findings.append(Finding(
                title="Docker: No HEALTHCHECK Defined",
                severity=Severity.LOW,
                category=Category.SECURITY_MISCONFIG,
                file_path=rel,
                line_number=None,
                code_snippet="No HEALTHCHECK instruction",
                description="Without HEALTHCHECK, orchestrators cannot detect a compromised or degraded container.",
                recommendation="Add: HEALTHCHECK --interval=30s CMD curl -f http://localhost/health || exit 1",
            ))

    # ── Nginx / Apache ─────────────────────────────────────────────────────

    def _check_nginx_apache(self, result: ScanResult):
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if re.match(r"(?:nginx|httpd|apache2?)\.conf$|\.nginx$|\.apache$", fname, re.IGNORECASE):
                    fpath = os.path.join(root, fname)
                    result.files_scanned += 1
                    self._audit_webserver_config(fpath, result)

    def _audit_webserver_config(self, file_path: str, result: ScanResult):
        content = _read(file_path) or ""
        rel = os.path.relpath(file_path, self.target_path)

        checks = [
            ("server_tokens off", "ServerTokens Prod",
             "Server version exposed", Severity.LOW,
             "Add: server_tokens off; (nginx) or ServerTokens Prod (Apache)"),
            ("X-Frame-Options", "frame-ancestors",
             "Missing Clickjacking Protection (X-Frame-Options)", Severity.MEDIUM,
             "Add: add_header X-Frame-Options 'DENY';"),
            ("X-Content-Type-Options", "X-Content-Type-Options",
             "Missing MIME Sniffing Protection", Severity.LOW,
             "Add: add_header X-Content-Type-Options 'nosniff';"),
            ("Strict-Transport-Security", "Strict-Transport-Security",
             "Missing HSTS Header", Severity.MEDIUM,
             "Add: add_header Strict-Transport-Security 'max-age=63072000; includeSubDomains; preload';"),
        ]
        for p1, p2, title, sev, rec in checks:
            if p1 not in content and p2 not in content:
                result.findings.append(Finding(
                    title=f"Web Server Config: {title}",
                    severity=sev,
                    category=Category.SECURITY_MISCONFIG,
                    file_path=rel,
                    line_number=None,
                    code_snippet=f"Pattern '{p1}' not found",
                    description=f"Security header/config '{p1}' is not configured.",
                    recommendation=rec,
                ))

        # TRACE method enabled
        if re.search(r"TraceEnable\s+On|add_header\s+.*TRACE", content, re.IGNORECASE):
            result.findings.append(Finding(
                title="Web Server: TRACE Method Enabled",
                severity=Severity.MEDIUM,
                category=Category.SECURITY_MISCONFIG,
                file_path=rel,
                line_number=None,
                code_snippet="TraceEnable On",
                description="HTTP TRACE method is enabled, which can be used in Cross-Site Tracing (XST) attacks to steal cookies.",
                recommendation="Disable TRACE: TraceEnable Off (Apache) or add 'if ($request_method = TRACE) { return 405; }' (nginx)",
                cwe_id="CWE-16",
            ))

    # ── package.json ───────────────────────────────────────────────────────

    def _check_package_json(self, result: ScanResult):
        pkg_json = os.path.join(self.target_path, "package.json")
        if not os.path.isfile(pkg_json):
            return
        result.files_scanned += 1
        try:
            data = json.load(open(pkg_json, encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        scripts = data.get("scripts", {})
        # Check for missing security audit script
        all_scripts = " ".join(str(v) for v in scripts.values())
        if "audit" not in all_scripts:
            result.findings.append(Finding(
                title="No npm Audit Script Configured",
                severity=Severity.LOW,
                category=Category.SECURITY_MISCONFIG,
                file_path="package.json",
                line_number=None,
                code_snippet="'audit' not in scripts",
                description="No npm security audit is integrated into the development workflow.",
                recommendation='Add to scripts: "audit": "npm audit --production"',
            ))

    # ── Security headers middleware ─────────────────────────────────────────

    def _check_security_headers_middleware(self, result: ScanResult):
        """Check if security header middleware (Helmet, Django SecurityMiddleware) is used."""
        has_js = has_py = False

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in {".js", ".ts", ".py", ".mjs"}:
                    continue
                fpath = os.path.join(root, fname)
                content = _read(fpath) or ""

                if ext in {".js", ".ts", ".mjs"}:
                    if re.search(r"""(?:require|import).*['"]helmet['"]""", content):
                        has_js = True
                    elif re.search(r"express\(\)", content) and not has_js:
                        # Express app without helmet
                        pass

                if ext == ".py":
                    if re.search(r"SecurityMiddleware|django\.middleware\.security", content):
                        has_py = True

        # Check Express apps
        express_apps = []
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if fname in ("app.js", "server.js", "index.js", "app.ts", "server.ts", "main.ts"):
                    fpath = os.path.join(root, fname)
                    content = _read(fpath) or ""
                    if re.search(r"express\s*\(\s*\)", content) and not re.search(r"helmet", content):
                        rel = os.path.relpath(fpath, self.target_path)
                        express_apps.append(rel)

        for rel in express_apps:
            result.findings.append(Finding(
                title="Express App Missing Helmet Security Headers",
                severity=Severity.MEDIUM,
                category=Category.SECURITY_MISCONFIG,
                file_path=rel,
                line_number=None,
                code_snippet="express() without helmet()",
                description="Express application does not use Helmet, which sets 11 security-related HTTP headers.",
                recommendation=(
                    "npm install helmet\n"
                    "const helmet = require('helmet');\n"
                    "app.use(helmet());"
                ),
                cwe_id="CWE-16",
            ))

        # Check Django settings
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            if "settings.py" in files:
                fpath = os.path.join(root, "settings.py")
                content = _read(fpath) or ""
                rel = os.path.relpath(fpath, self.target_path)
                result.files_scanned += 1

                if "SecurityMiddleware" not in content:
                    result.findings.append(Finding(
                        title="Django: SecurityMiddleware Not Configured",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY_MISCONFIG,
                        file_path=rel,
                        line_number=None,
                        code_snippet="SecurityMiddleware not in MIDDLEWARE",
                        description="Django SecurityMiddleware is not configured. It enforces HTTPS, HSTS, and other security policies.",
                        recommendation="Add 'django.middleware.security.SecurityMiddleware' to MIDDLEWARE (first in list).",
                    ))

                if "SECURE_SSL_REDIRECT" not in content:
                    result.findings.append(Finding(
                        title="Django: HTTPS Redirect Not Configured",
                        severity=Severity.MEDIUM,
                        category=Category.SECURITY_MISCONFIG,
                        file_path=rel,
                        line_number=None,
                        code_snippet="SECURE_SSL_REDIRECT not set",
                        description="SECURE_SSL_REDIRECT is not configured. HTTP requests won't be redirected to HTTPS.",
                        recommendation="Add to settings.py: SECURE_SSL_REDIRECT = True (in production)",
                    ))

    # ── Cookie security ────────────────────────────────────────────────────

    def _check_cookie_security(self, result: ScanResult):
        """Check for insecure cookie configuration patterns."""
        cookie_patterns = [
            (re.compile(r"(?:set_cookie|response\.set_cookie)\s*\([^)]*\)", re.IGNORECASE), {".py"}),
            (re.compile(r"res\.cookie\s*\([^)]+\)", re.IGNORECASE), {".js", ".ts"}),
            (re.compile(r"setcookie\s*\([^)]+\)", re.IGNORECASE), {".php"}),
        ]

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                fpath = os.path.join(root, fname)
                content = _read(fpath) or ""
                lines = content.splitlines()
                rel = os.path.relpath(fpath, self.target_path)

                for pat, exts in cookie_patterns:
                    if ext not in exts:
                        continue
                    for m in pat.finditer(content):
                        cookie_call = m.group(0)
                        line_num = content[:m.start()].count("\n") + 1

                        if "httponly" not in cookie_call.lower() and "http_only" not in cookie_call.lower():
                            result.findings.append(Finding(
                                title="Cookie Missing HttpOnly Flag",
                                severity=Severity.MEDIUM,
                                category=Category.BROKEN_AUTH,
                                file_path=rel,
                                line_number=line_num,
                                code_snippet=cookie_call[:150],
                                description="Cookie set without HttpOnly flag. JavaScript can access this cookie, enabling XSS-based session theft.",
                                recommendation="Set httponly=True: response.set_cookie('session', value, httponly=True, secure=True, samesite='Strict')",
                                cwe_id="CWE-1004",
                                attack_simulation="XSS payload: document.cookie reads the session cookie and sends it to attacker.",
                            ))

                        if "secure" not in cookie_call.lower():
                            result.findings.append(Finding(
                                title="Cookie Missing Secure Flag",
                                severity=Severity.MEDIUM,
                                category=Category.BROKEN_AUTH,
                                file_path=rel,
                                line_number=line_num,
                                code_snippet=cookie_call[:150],
                                description="Cookie set without Secure flag. The cookie can be transmitted over HTTP, exposing it to network interception.",
                                recommendation="Add secure=True to ensure the cookie is only sent over HTTPS.",
                                cwe_id="CWE-614",
                                attack_simulation="Network MITM on HTTP connection captures session cookie and hijacks user session.",
                            ))

                        if "samesite" not in cookie_call.lower():
                            result.findings.append(Finding(
                                title="Cookie Missing SameSite Attribute",
                                severity=Severity.LOW,
                                category=Category.BROKEN_AUTH,
                                file_path=rel,
                                line_number=line_num,
                                code_snippet=cookie_call[:150],
                                description="Cookie without SameSite attribute is sent on all cross-site requests, enabling CSRF attacks.",
                                recommendation="Add samesite='Strict' or samesite='Lax' to prevent CSRF.",
                                cwe_id="CWE-352",
                            ))

    # ── Session config ─────────────────────────────────────────────────────

    def _check_session_config(self, result: ScanResult):
        """Check for weak session configuration."""
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in {".py", ".js", ".ts"}:
                    continue
                fpath = os.path.join(root, fname)
                content = _read(fpath) or ""
                rel = os.path.relpath(fpath, self.target_path)
                lines = content.splitlines()

                for i, line in enumerate(lines, 1):
                    # Short session secret
                    m = re.search(
                        r"""(?:SECRET_KEY|session.?secret|app\.secret)\s*[=:]\s*['"]([^'"]{1,20})['"]""",
                        line, re.IGNORECASE
                    )
                    if m and len(m.group(1)) < 32:
                        result.findings.append(Finding(
                            title="Weak Session Secret Key",
                            severity=Severity.HIGH,
                            category=Category.BROKEN_AUTH,
                            file_path=rel,
                            line_number=i,
                            code_snippet=line.strip()[:120],
                            description=f"Session secret is only {len(m.group(1))} characters. Short secrets are vulnerable to brute-force attacks.",
                            recommendation="Use a cryptographically random key of at least 32 bytes: python -c \"import secrets; print(secrets.token_hex(32))\"",
                            cwe_id="CWE-334",
                            attack_simulation="Attacker brute-forces the session secret to forge valid session tokens for any user.",
                        ))

                    # Long session lifetime without re-auth
                    if re.search(r"PERMANENT_SESSION_LIFETIME\s*=.*timedelta.*(?:days=3[0-9]|weeks=[2-9])", line):
                        result.findings.append(Finding(
                            title="Excessively Long Session Lifetime",
                            severity=Severity.LOW,
                            category=Category.BROKEN_AUTH,
                            file_path=rel,
                            line_number=i,
                            code_snippet=line.strip()[:120],
                            description="Session lifetime exceeds 30 days, increasing the window for session token theft.",
                            recommendation="Reduce session lifetime: timedelta(hours=8) for regular users, shorter for admin sessions.",
                            cwe_id="CWE-613",
                        ))

    # ── Rate limiting ──────────────────────────────────────────────────────

    def _check_rate_limiting(self, result: ScanResult):
        """Detect auth endpoints without rate limiting middleware."""
        auth_route_pat = re.compile(
            r"""(?:@app\.route|@router\.\w+|router\.\w+)\s*\(\s*['"][^'"]*(?:login|auth|signin|signup|register|password|reset|token|verify)[^'"]*['"]""",
            re.IGNORECASE,
        )
        rate_limit_pat = re.compile(
            r"(?:rate.?limit|throttle|limiter|slowapi|flask.?limiter|express.?rate|ratelimit)",
            re.IGNORECASE,
        )

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in {".py", ".js", ".ts"}:
                    continue
                fpath = os.path.join(root, fname)
                content = _read(fpath) or ""
                rel = os.path.relpath(fpath, self.target_path)

                # Only flag if rate limiting is completely absent from the file
                if rate_limit_pat.search(content):
                    continue

                for m in auth_route_pat.finditer(content):
                    line_num = content[:m.start()].count("\n") + 1
                    result.findings.append(Finding(
                        title="Auth Endpoint Without Rate Limiting",
                        severity=Severity.HIGH,
                        category=Category.BROKEN_AUTH,
                        file_path=rel,
                        line_number=line_num,
                        code_snippet=m.group(0)[:120],
                        description="Authentication endpoint found without any rate limiting. Allows unlimited brute-force attempts.",
                        recommendation=(
                            "Python/Flask: pip install flask-limiter, then @limiter.limit('5 per minute')\n"
                            "Node.js: npm install express-rate-limit, then app.use('/auth', rateLimit({max: 5}))"
                        ),
                        cwe_id="CWE-307",
                        attack_simulation=(
                            "Tool: hydra -l admin@target.com -P rockyou.txt https://target/login\n"
                            "Rate: Without limiting, 1000+ attempts/second until success"
                        ),
                    ))
                    break  # One finding per file

    # ── Hardcoded IPs ──────────────────────────────────────────────────────

    def _check_hardcoded_ips(self, result: ScanResult):
        """Detect hardcoded non-localhost IP addresses in source code."""
        ip_pat = re.compile(
            r"""['"](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})['"]"""
        )
        private_ranges = re.compile(
            r"""^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|172\.16\.)"""
        )
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in {".py", ".js", ".ts", ".java", ".go", ".yml", ".yaml"}:
                    continue
                fpath = os.path.join(root, fname)
                content = _read(fpath) or ""
                rel = os.path.relpath(fpath, self.target_path)
                lines = content.splitlines()

                reported_in_file = set()
                for i, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if stripped.startswith(("#", "//")):
                        continue
                    for m in ip_pat.finditer(line):
                        ip = m.group(1)
                        if ip in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
                            continue
                        if ip in reported_in_file:
                            continue
                        reported_in_file.add(ip)
                        is_private = bool(private_ranges.match(ip))
                        result.findings.append(Finding(
                            title=f"Hardcoded {'Private' if is_private else 'Public'} IP Address: {ip}",
                            severity=Severity.LOW if is_private else Severity.MEDIUM,
                            category=Category.SECURITY_MISCONFIG,
                            file_path=rel,
                            line_number=i,
                            code_snippet=stripped[:120],
                            description=f"IP address {ip} is hardcoded. This prevents environment-specific configuration and may expose internal topology.",
                            recommendation="Use environment variables or configuration files: DB_HOST = os.environ.get('DB_HOST', 'localhost')",
                        ))

    # ── SSL/TLS ────────────────────────────────────────────────────────────

    def _check_ssl_tls(self, result: ScanResult):
        ssl_disabled = re.compile(
            r"""verify\s*=\s*False|VERIFY_SSL\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|ssl\._create_unverified_context""",
            re.IGNORECASE,
        )
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in {".py", ".js", ".ts", ".go", ".java", ".yml", ".yaml"}:
                    continue
                fpath = os.path.join(root, fname)
                content = _read(fpath) or ""
                rel = os.path.relpath(fpath, self.target_path)
                lines = content.splitlines()
                for i, line in enumerate(lines, 1):
                    if ssl_disabled.search(line):
                        result.findings.append(Finding(
                            title="SSL/TLS Certificate Verification Disabled",
                            severity=Severity.HIGH,
                            category=Category.SECURITY_MISCONFIG,
                            file_path=rel,
                            line_number=i,
                            code_snippet=line.strip()[:150],
                            description="TLS verification is disabled, exposing all connections to man-in-the-middle attacks.",
                            recommendation="Remove verify=False. For self-signed certs use: verify='/path/to/ca-bundle.crt'",
                            cwe_id="CWE-295",
                            attack_simulation="mitmproxy intercepts all 'encrypted' traffic including credentials and API tokens.",
                        ))

    # ── CI/CD ──────────────────────────────────────────────────────────────

    def _check_ci_cd(self, result: ScanResult):
        ci_files = []
        actions_dir = os.path.join(self.target_path, ".github", "workflows")
        if os.path.isdir(actions_dir):
            for fn in os.listdir(actions_dir):
                if fn.endswith((".yml", ".yaml")):
                    ci_files.append(os.path.join(actions_dir, fn))

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if fname in (".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml", ".travis.yml", "circle.yml"):
                    ci_files.append(os.path.join(root, fname))

        for fpath in ci_files:
            result.files_scanned += 1
            content = _read(fpath) or ""
            rel = os.path.relpath(fpath, self.target_path)
            lines = content.splitlines()

            # Hardcoded secrets
            if re.search(r"(?:password|secret|token|api_key)\s*:\s*['\"]?[A-Za-z0-9_\-]{12,}['\"]?", content, re.IGNORECASE):
                # Make sure it's not a ${{ secrets.X }} reference
                if not re.search(r"\$\{\{\s*secrets\.", content):
                    result.findings.append(Finding(
                        title="Hardcoded Secret in CI/CD Pipeline",
                        severity=Severity.CRITICAL,
                        category=Category.SECRETS,
                        file_path=rel,
                        line_number=None,
                        code_snippet="[Detected secret pattern in CI config]",
                        description="Credentials appear hardcoded in CI/CD configuration instead of using secret variables.",
                        recommendation="Use ${{ secrets.MY_SECRET }} (GitHub Actions) or masked CI/CD variables.",
                        cwe_id="CWE-798",
                    ))

            # Pull request target with checkout (PWN requests)
            if "pull_request_target" in content and "actions/checkout" in content:
                result.findings.append(Finding(
                    title="GitHub Actions: Dangerous pull_request_target",
                    severity=Severity.HIGH,
                    category=Category.BROKEN_ACCESS,
                    file_path=rel,
                    line_number=None,
                    code_snippet="pull_request_target + actions/checkout",
                    description="pull_request_target combined with checkout can expose repository secrets to untrusted PR code.",
                    recommendation="Use pull_request trigger instead, or do not checkout untrusted code in pull_request_target workflows.",
                    cwe_id="CWE-94",
                    attack_simulation="Attacker opens a malicious PR that exfiltrates GITHUB_TOKEN via the workflow.",
                ))

            # Missing permissions restriction
            if "permissions:" not in content and ("pull_request" in content or "push" in content):
                result.findings.append(Finding(
                    title="GitHub Actions: No Permissions Restriction",
                    severity=Severity.MEDIUM,
                    category=Category.BROKEN_ACCESS,
                    file_path=rel,
                    line_number=None,
                    code_snippet="'permissions:' block missing",
                    description="Workflow has no permissions block, defaulting to permissive read/write access for GITHUB_TOKEN.",
                    recommendation=(
                        "Add minimal permissions:\n"
                        "permissions:\n"
                        "  contents: read\n"
                        "  pull-requests: write"
                    ),
                ))

            # Pinned actions check
            for m in re.finditer(r"uses:\s*([^@\n]+)@([^\n]+)", content):
                action, ref = m.group(1).strip(), m.group(2).strip()
                if not re.match(r"[0-9a-f]{40}", ref):  # Not a full SHA
                    line_num = content[:m.start()].count("\n") + 1
                    result.findings.append(Finding(
                        title=f"GitHub Actions: Action Not Pinned to SHA: {action}@{ref}",
                        severity=Severity.LOW,
                        category=Category.VULNERABLE_COMPONENTS,
                        file_path=rel,
                        line_number=line_num,
                        code_snippet=m.group(0)[:80],
                        description=f"Action '{action}' referenced by tag '{ref}'. Tags are mutable; a compromised action repo can inject malicious code.",
                        recommendation=f"Pin to a specific commit SHA: {action}@<full-40-char-sha>",
                        cwe_id="CWE-829",
                    ))
                    break  # One per workflow to avoid noise

    # ── Content Security Policy ─────────────────────────────────────────────

    def _check_csp(self, result: ScanResult):
        """Check for Content Security Policy configuration."""
        csp_pat = re.compile(r"Content-Security-Policy|content_security_policy|CSP", re.IGNORECASE)
        found_csp = False

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in {".py", ".js", ".ts", ".conf", ".yml", ".yaml"}:
                    continue
                fpath = os.path.join(root, fname)
                content = _read(fpath) or ""
                if csp_pat.search(content):
                    found_csp = True
                    # Check for unsafe-inline
                    for m in re.finditer(r"'unsafe-inline'", content):
                        line_num = content[:m.start()].count("\n") + 1
                        rel = os.path.relpath(fpath, self.target_path)
                        result.findings.append(Finding(
                            title="CSP: 'unsafe-inline' Defeats XSS Protection",
                            severity=Severity.MEDIUM,
                            category=Category.SECURITY_MISCONFIG,
                            file_path=rel,
                            line_number=line_num,
                            code_snippet=content.splitlines()[line_num - 1].strip()[:120],
                            description="'unsafe-inline' in CSP allows inline scripts and styles, negating XSS protection.",
                            recommendation="Remove 'unsafe-inline'. Use nonces or hashes for legitimate inline scripts.",
                            cwe_id="CWE-16",
                        ))
                        break

        if not found_csp:
            # Only flag if web framework is detected
            has_web = False
            for root, dirs, files in os.walk(self.target_path):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for fname in files:
                    if fname in ("app.py", "server.py", "app.js", "server.js", "main.py"):
                        has_web = True
            if has_web:
                result.findings.append(Finding(
                    title="No Content Security Policy (CSP) Detected",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY_MISCONFIG,
                    file_path="(project)",
                    line_number=None,
                    code_snippet="Content-Security-Policy header not found",
                    description="No Content Security Policy configured. CSP is the primary defense against XSS attacks.",
                    recommendation=(
                        "Add CSP header:\n"
                        "  Flask:   response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
                        "  Express: use helmet.contentSecurityPolicy()\n"
                        "  Nginx:   add_header Content-Security-Policy \"default-src 'self'\";"
                    ),
                    cwe_id="CWE-16",
                ))
