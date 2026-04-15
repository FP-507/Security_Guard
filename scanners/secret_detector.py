"""
Secret Detector — finds API keys, tokens, passwords, and high-entropy strings.

Improvements over v1:
- Per-charset entropy analysis (base64, hex, alphanum) for fewer false positives
- Expanded to 30+ service-specific patterns
- False positive suppression: skips comments, docs, test fixtures, placeholder values
- Multi-pattern deduplication per file/line
- High-risk file heuristics with smarter value filtering
- UUIDs and hashes excluded from high-entropy alerts
"""

import math
import os
import re
import time
from .base import BaseScanner, ScanResult, Finding, Severity, Category

# ── Skip sets ──────────────────────────────────────────────────────────────
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", "vendor", "site-packages",
    "coverage", "htmlcov", ".pytest_cache",
}
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4",
    ".avi", ".mov", ".webm", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo", ".class",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
}
MAX_FILE_SIZE = 500_000

# Values that are always safe to ignore (placeholders, examples, test data)
PLACEHOLDER_PATTERNS = re.compile(
    r"""(?xi)
    ^(?:
        your[-_]?\w+         # your_api_key
      | my[-_]?\w+           # my_secret
      | <[^>]+>              # <YOUR_KEY>
      | \{[^}]+\}            # {API_KEY}
      | \[\w+\]              # [TOKEN]
      | xxx+                 # xxx / xxxx
      | \*{3,}               # ***
      | changeme
      | placeholder
      | example
      | sample
      | dummy
      | fake
      | test[-_]?\w*
      | demo[-_]?\w*
      | replace[-_]?(?:with|me|this)
      | (?:todo|fixme)\b
      | (?:none|null|undefined|false|true|n/?a)
      | (?:0{8,}|1{8,})     # 00000000 / 11111111
    )$
    """,
    re.IGNORECASE,
)

# High-risk filenames that likely contain real secrets
HIGH_RISK_FILES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.test", ".env.backup", ".env.example.real",
    ".npmrc", ".pypirc", ".netrc", ".pgpass", ".s3cfg",
    "credentials.json", "credentials.yml", "credentials.yaml",
    "service-account.json", "service_account.json",
    "google-credentials.json", "gcp-key.json",
    "secrets.json", "secrets.yml", "secrets.yaml",
    "config.local.js", "config.local.ts", "local.settings.json",
    "docker-compose.override.yml", "docker-compose.override.yaml",
}

# Extension allowlist for scanning
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".swift",
    ".kt", ".rs", ".scala", ".env", ".yml", ".yaml",
    ".json", ".toml", ".cfg", ".ini", ".conf", ".config",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".pem",
    ".key", ".crt", ".p12", ".pfx", ".xml", ".tf",
    ".tfvars", ".properties", ".gradle", ".sbt",
}

# UUID pattern — exclude from entropy detection
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Common hash patterns — exclude from entropy detection
HASH_PATTERN = re.compile(
    r"^[0-9a-f]{32,64}$",
    re.IGNORECASE,
)

# ── Entropy helpers ────────────────────────────────────────────────────────

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
HEX_CHARS    = set("0123456789abcdefABCDEF")


def shannon_entropy(s: str, charset: set = None) -> float:
    """Shannon entropy of a string, optionally within a given charset."""
    if charset:
        s = "".join(c for c in s if c in charset)
    if len(s) < 8:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def is_high_entropy_secret(value: str) -> tuple[bool, str]:
    """
    Returns (is_secret, reason) using per-charset entropy analysis.
    False positive guards:
    - UUIDs are not secrets
    - Pure hex hashes (md5/sha*) are not secrets
    - Low charset entropy means it's a regular word, not a key
    """
    if len(value) < 16:
        return False, ""
    if UUID_PATTERN.match(value):
        return False, ""
    if HASH_PATTERN.match(value) and len(value) in (32, 40, 56, 64):
        return False, ""  # MD5/SHA hash — probably an intentional hash, not a key
    if PLACEHOLDER_PATTERNS.match(value):
        return False, ""

    # Check base64 charset entropy
    b64_ratio = sum(1 for c in value if c in BASE64_CHARS) / len(value)
    if b64_ratio > 0.85 and len(value) >= 20:
        entropy = shannon_entropy(value, BASE64_CHARS)
        if entropy > 4.8:
            return True, f"high entropy base64-like string (H={entropy:.1f})"

    # Check hex charset entropy
    hex_ratio = sum(1 for c in value if c in HEX_CHARS) / len(value)
    if hex_ratio > 0.95 and len(value) >= 32:
        entropy = shannon_entropy(value, HEX_CHARS)
        if entropy > 3.5:
            # Still exclude pure hashes
            if not HASH_PATTERN.match(value):
                return True, f"high entropy hex string (H={entropy:.1f})"

    return False, ""


# ── Secret Patterns ────────────────────────────────────────────────────────

class SecretPattern:
    def __init__(self, name, pattern, severity, min_len=8, notes=None):
        self.name = name
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
        self.min_len = min_len
        self.notes = notes


SECRET_PATTERNS = [
    # ── Cloud: AWS ──────────────────────────────────────────────────────
    SecretPattern("AWS Access Key ID",
        r"(?:^|['\"\s=:])(?P<secret>AKIA[0-9A-Z]{16})(?:['\"\s]|$)",
        Severity.CRITICAL, min_len=20),
    SecretPattern("AWS Secret Access Key",
        r"(?:aws.?secret.?access.?key|aws.?secret)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9/+]{40})['\"]?",
        Severity.CRITICAL, min_len=40),
    SecretPattern("AWS Session Token",
        r"(?:aws.?session.?token)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9/+]{100,})['\"]?",
        Severity.CRITICAL, min_len=100),

    # ── Cloud: GCP ──────────────────────────────────────────────────────
    SecretPattern("GCP API Key",
        r"(?P<secret>AIza[0-9A-Za-z_-]{35})",
        Severity.HIGH, min_len=39),
    SecretPattern("GCP OAuth Client Secret",
        r"(?:client.?secret)\s*[=:]\s*['\"](?P<secret>GOCSPX-[A-Za-z0-9_-]{28,})['\"]",
        Severity.HIGH, min_len=30),

    # ── Cloud: Azure ────────────────────────────────────────────────────
    SecretPattern("Azure Connection String",
        r"(?P<secret>DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,})",
        Severity.CRITICAL, min_len=80),
    SecretPattern("Azure SAS Token",
        r"(?P<secret>sv=\d{4}-\d{2}-\d{2}&(?:ss|srt|se|sp|spr|sig)=[A-Za-z0-9%+/=&]+)",
        Severity.HIGH, min_len=40),

    # ── Version control ─────────────────────────────────────────────────
    SecretPattern("GitHub Personal Access Token",
        r"(?P<secret>gh[pousr]_[A-Za-z0-9_]{36,255})",
        Severity.CRITICAL, min_len=40),
    SecretPattern("GitHub App Token",
        r"(?P<secret>ghs_[A-Za-z0-9_]{36,})",
        Severity.CRITICAL, min_len=40),
    SecretPattern("GitLab Personal Access Token",
        r"(?P<secret>glpat-[A-Za-z0-9_-]{20,})",
        Severity.CRITICAL, min_len=26),
    SecretPattern("Bitbucket App Password",
        r"(?P<secret>ATBB[A-Za-z0-9_]{32,})",
        Severity.HIGH, min_len=36),

    # ── Messaging ───────────────────────────────────────────────────────
    SecretPattern("Slack Bot Token",
        r"(?P<secret>xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24,})",
        Severity.CRITICAL, min_len=60),
    SecretPattern("Slack Webhook URL",
        r"(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24,})",
        Severity.HIGH, min_len=70),
    SecretPattern("Discord Bot Token",
        r"(?P<secret>[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,})",
        Severity.HIGH, min_len=58),
    SecretPattern("Telegram Bot Token",
        r"(?<!\d)(?P<secret>\d{8,10}:[A-Za-z0-9_-]{35})(?!\d)",
        Severity.HIGH, min_len=45),

    # ── Payment ─────────────────────────────────────────────────────────
    SecretPattern("Stripe Live Secret Key",
        r"(?P<secret>sk_live_[0-9a-zA-Z]{24,})",
        Severity.CRITICAL, min_len=30),
    SecretPattern("Stripe Publishable Key",
        r"(?P<secret>pk_live_[0-9a-zA-Z]{24,})",
        Severity.MEDIUM, min_len=30),
    SecretPattern("Stripe Restricted Key",
        r"(?P<secret>rk_live_[0-9a-zA-Z]{24,})",
        Severity.CRITICAL, min_len=30),
    SecretPattern("PayPal Client Secret",
        r"(?:paypal.?(?:secret|client.?secret))\s*[=:]\s*['\"](?P<secret>[A-Za-z0-9_.-]{30,})['\"]",
        Severity.HIGH, min_len=30),

    # ── Email / SMS ─────────────────────────────────────────────────────
    SecretPattern("SendGrid API Key",
        r"(?P<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})",
        Severity.CRITICAL, min_len=69),
    SecretPattern("Mailgun API Key",
        r"(?P<secret>key-[0-9a-zA-Z]{32})",
        Severity.HIGH, min_len=36),
    SecretPattern("Twilio Account SID",
        r"(?P<secret>AC[a-fA-F0-9]{32})",
        Severity.HIGH, min_len=34),
    SecretPattern("Twilio Auth Token",
        r"(?:twilio.?(?:auth.?token|token))\s*[=:]\s*['\"](?P<secret>[a-fA-F0-9]{32})['\"]",
        Severity.CRITICAL, min_len=32),

    # ── Authentication services ─────────────────────────────────────────
    SecretPattern("OAuth2 Bearer Token",
        r"(?:Bearer\s+|Authorization:\s*Bearer\s+)(?P<secret>[A-Za-z0-9._-]{20,})",
        Severity.HIGH, min_len=20),
    SecretPattern("NPM Auth Token",
        r"(?P<secret>//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_-]{36,})",
        Severity.CRITICAL, min_len=50),
    SecretPattern("PyPI API Token",
        r"(?P<secret>pypi-[A-Za-z0-9_-]{40,})",
        Severity.HIGH, min_len=44),
    SecretPattern("HuggingFace Token",
        r"(?P<secret>hf_[A-Za-z0-9]{34,})",
        Severity.HIGH, min_len=36),

    # ── Database & Infrastructure ────────────────────────────────────────
    SecretPattern("Database Connection String with Credentials",
        r"(?P<secret>(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql|amqp|rabbitmq|clickhouse)://[^\s'\"]{8,}:[^\s'\"@]{3,}@[^\s'\"]+)",
        Severity.CRITICAL, min_len=20),
    SecretPattern("Heroku API Key",
        r"(?:heroku.*(?:api.?key|token))\s*[=:]\s*['\"]?(?P<secret>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?",
        Severity.CRITICAL, min_len=36),
    SecretPattern("DigitalOcean Personal Access Token",
        r"(?P<secret>dop_v1_[A-Za-z0-9]{64})",
        Severity.CRITICAL, min_len=72),

    # ── Cryptographic keys ───────────────────────────────────────────────
    SecretPattern("RSA/EC Private Key",
        r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)",
        Severity.CRITICAL, min_len=10),
    SecretPattern("PGP Private Key Block",
        r"(?P<secret>-----BEGIN PGP PRIVATE KEY BLOCK-----)",
        Severity.CRITICAL, min_len=10),

    # ── JWT ─────────────────────────────────────────────────────────────
    SecretPattern("Hardcoded JWT Token",
        r"(?P<secret>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
        Severity.HIGH, min_len=50),

    # ── URL with credentials ─────────────────────────────────────────────
    SecretPattern("Password in URL",
        r"(?P<secret>https?://[^:\s@]{3,}:[^@\s]{6,}@[^\s'\"]{5,})",
        Severity.HIGH, min_len=20),

    # ── Generic strong API keys ──────────────────────────────────────────
    SecretPattern("Generic API Key Assignment",
        r"""(?:api.?key|api.?secret|app.?secret|client.?secret|consumer.?(?:key|secret))\s*[=:]\s*['"](?P<secret>[A-Za-z0-9_\-+/]{20,})['"]\s*(?:,|;|$)""",
        Severity.HIGH, min_len=20),
]

# ── Sensitive key names for .env / config files ────────────────────────────

SENSITIVE_KEY_RE = re.compile(
    r"""(?xi)
    (?:
        password | passwd | pass(?!_by) | secret | private.?key
      | api.?key | api.?secret | access.?key | access.?secret
      | auth.?token | auth.?secret | bearer.?token | client.?secret
      | refresh.?token | signing.?key | encryption.?key
      | database.?url | db.?pass | db.?pwd
      | smtp.?pass | mail.?pass
      | jwt.?secret | session.?secret | cookie.?secret
    )
    """,
    re.IGNORECASE,
)


class SecretDetector(BaseScanner):
    name = "Secret Detector"

    def scan(self) -> ScanResult:
        start = time.time()
        result = ScanResult(scanner_name=self.name)

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()

                # Check extension
                if ext in BINARY_EXTENSIONS:
                    continue
                if ext not in SCAN_EXTENSIONS and fname not in HIGH_RISK_FILES and not fname.startswith(".env"):
                    continue

                try:
                    if os.path.getsize(fpath) > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                is_high_risk = (
                    fname in HIGH_RISK_FILES
                    or fname.startswith(".env")
                    or ext in (".pem", ".key", ".p12", ".pfx")
                )

                findings = self._scan_file(fpath, is_high_risk)
                result.findings.extend(findings)
                result.files_scanned += 1

        result.scan_time_seconds = time.time() - start
        return result

    def _scan_file(self, file_path: str, is_high_risk: bool) -> list[Finding]:
        findings = []
        rel_path = os.path.relpath(file_path, self.target_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            return findings

        # Track (line_number) already reported to avoid duplicates
        reported_lines: set[int] = set()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue

            # Skip full-line comments in common languages
            if stripped.startswith(("#", "//", "*", "<!--", "--", "/*")):
                continue

            # ── High-risk file: key=value sensitive assignment ──────────
            if is_high_risk and i not in reported_lines:
                kv_match = re.match(
                    r"""^([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*['"]?([^'"\s#][^\s#]{5,})['"]?\s*(?:#.*)?$""",
                    stripped,
                )
                if kv_match:
                    key, value = kv_match.groups()
                    if SENSITIVE_KEY_RE.search(key) and not PLACEHOLDER_PATTERNS.match(value):
                        masked = value[:4] + "*" * min(len(value) - 4, 16)
                        findings.append(Finding(
                            title=f"Sensitive Value in {os.path.basename(file_path)}: {key}",
                            severity=Severity.CRITICAL,
                            category=Category.SECRETS,
                            file_path=rel_path,
                            line_number=i,
                            code_snippet=f"{key}=[REDACTED {masked}]",
                            description=f"Sensitive key '{key}' with a non-trivial value found in a high-risk configuration file.",
                            recommendation=(
                                "- Remove the real value; add this file to .gitignore\n"
                                "- Use a secrets manager or runtime environment variable injection\n"
                                "- Rotate the exposed credential immediately"
                            ),
                            cwe_id="CWE-798",
                            attack_simulation="If this file is committed to git, any clone of the repo immediately compromises these credentials.",
                        ))
                        reported_lines.add(i)
                        continue

            # ── Pattern-based detection ─────────────────────────────────
            if i in reported_lines:
                continue

            for sp in SECRET_PATTERNS:
                m = sp.regex.search(line)
                if not m:
                    continue

                try:
                    secret_value = m.group("secret")
                except IndexError:
                    secret_value = m.group(0)

                if len(secret_value) < sp.min_len:
                    continue
                if PLACEHOLDER_PATTERNS.match(secret_value.strip("'\"` ")):
                    continue

                masked = secret_value[:4] + "*" * min(len(secret_value) - 4, 20)
                findings.append(Finding(
                    title=sp.name,
                    severity=sp.severity,
                    category=Category.SECRETS,
                    file_path=rel_path,
                    line_number=i,
                    code_snippet=f"[REDACTED] {masked}",
                    description=f"Detected {sp.name} pattern. If real, this credential is exposed.",
                    recommendation=(
                        "- Remove from source code and git history (git-filter-repo or BFG)\n"
                        "- Rotate the credential immediately in the service's dashboard\n"
                        "- Store secrets in environment variables or a secrets manager"
                    ),
                    cwe_id="CWE-798",
                    attack_simulation=f"An exposed {sp.name} grants immediate access to the associated service. Search engines and bot scanners index public repos continuously.",
                ))
                reported_lines.add(i)
                break  # One finding per line

            # ── High-entropy string detection ───────────────────────────
            if i in reported_lines:
                continue

            # Look for assignments with suspicious values
            m = re.search(
                r"""(?:=|:)\s*['"`]([A-Za-z0-9+/=_\-]{24,})[`'"]\s*(?:,|;|\}|$)""",
                line,
            )
            if m:
                candidate = m.group(1)
                is_secret, reason = is_high_entropy_secret(candidate)
                if is_secret:
                    masked = candidate[:4] + "*" * min(len(candidate) - 4, 20)
                    findings.append(Finding(
                        title="High-Entropy String — Possible Hardcoded Secret",
                        severity=Severity.MEDIUM,
                        category=Category.SECRETS,
                        file_path=rel_path,
                        line_number=i,
                        code_snippet=f"[REDACTED] {masked}",
                        description=f"A {reason} was found assigned to a variable. This pattern is commonly used for API keys and tokens.",
                        recommendation=(
                            "- Verify whether this is a secret\n"
                            "- If so, move it to environment variables\n"
                            "- If it is a hash or non-sensitive constant, add a comment to suppress future alerts"
                        ),
                        cwe_id="CWE-798",
                        attack_simulation="High-entropy strings in source code frequently turn out to be credentials that grant service access.",
                    ))
                    reported_lines.add(i)

        return findings
