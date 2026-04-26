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
from .base import (
    BaseScanner, ScanResult, Finding, Severity, Category, Confidence,
    should_skip_dir, should_skip_file,
)
from core.secret_verifiers import verify as verify_secret_live

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


# ── Keyword pre-filter (GitLeaks-style) ────────────────────────────────────
# A line is only worth running through the expensive regex/entropy passes if
# it mentions a credential-related keyword. This is a ~10x speedup on large
# repos and dramatically reduces false positives in code that happens to
# contain high-entropy strings (UUIDs, hashes, base64 image data) but is not
# in a credential context.

CREDENTIAL_KEYWORDS = re.compile(
    r"""(?xi)
    \b(?:
        api[-_ ]?key | api[-_ ]?secret | apikey | apisecret
      | access[-_ ]?key | access[-_ ]?token | accesskey
      | secret[-_ ]?key | secretkey | secret[-_ ]?token
      | auth[-_ ]?token | auth[-_ ]?key | authorization | bearer
      | client[-_ ]?secret | client[-_ ]?id
      | private[-_ ]?key | privatekey
      | password | passwd | passphrase
      | token | credential | credentials
      | session[-_ ]?id | session[-_ ]?key
      | encryption[-_ ]?key | signing[-_ ]?key | jwt
      | webhook | bot[-_ ]?token
      | refresh[-_ ]?token | id[-_ ]?token
      | dsn | connection[-_ ]?string
      | aws_ | gcp_ | azure_ | github_
    )\b
    """
)


def has_credential_context(line: str) -> bool:
    """True if a line mentions any credential-related keyword.

    Used as a pre-filter for the entropy-based generic detector — without it,
    scanning a 100k-LOC repo flags every UUID and base64 image as a possible
    secret. The pattern-specific detectors (AWS, Stripe, etc.) bypass this
    filter because their prefixes are unambiguous.
    """
    return bool(CREDENTIAL_KEYWORDS.search(line))


# ── Secret Patterns ────────────────────────────────────────────────────────

class SecretPattern:
    def __init__(self, name, pattern, severity, min_len=8, notes=None,
                 validator=None, confidence=Confidence.HIGH):
        self.name = name
        self.regex = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
        self.min_len = min_len
        self.notes = notes
        # validator(value) -> bool. If provided and returns False, the match
        # is discarded as a false positive.
        self.validator = validator
        # Default confidence when the pattern matches and validator passes.
        self.confidence = confidence


# ── Format validators ──────────────────────────────────────────────────────
# Each returns True if the candidate value is structurally plausible.

def _validate_jwt(value: str) -> bool:
    """JWT must be 3 base64url-encoded segments and the header must decode
    to a JSON object with at least an 'alg' field."""
    import base64, json
    parts = value.split(".")
    if len(parts) != 3:
        return False
    header_b64 = parts[0]
    # base64url padding fix
    pad = "=" * (-len(header_b64) % 4)
    try:
        header_bytes = base64.urlsafe_b64decode(header_b64 + pad)
        header = json.loads(header_bytes)
    except Exception:
        return False
    return isinstance(header, dict) and "alg" in header


def _validate_aws_access_key(value: str) -> bool:
    """AWS access key IDs are exactly 20 chars, all uppercase alnum, and
    start with a documented prefix (AKIA, ASIA, AROA, AIDA, ANPA, ANVA)."""
    if len(value) != 20:
        return False
    if not value.isupper() and not value.isalnum():
        return False
    return value[:4] in {"AKIA", "ASIA", "AROA", "AIDA", "ANPA", "ANVA"}


def _validate_stripe_key(value: str) -> bool:
    """Stripe keys start with sk_/pk_/rk_ + (live|test)_ + at least 24 chars."""
    if not (value.startswith(("sk_", "pk_", "rk_"))):
        return False
    rest = value.split("_", 2)
    if len(rest) < 3:
        return False
    return rest[1] in {"live", "test"} and len(rest[2]) >= 24


def _validate_github_token(value: str) -> bool:
    """GitHub PATs: ghp_/gho_/ghu_/ghs_/ghr_ + 36 base62 chars."""
    if len(value) < 40:
        return False
    prefix = value[:4]
    if prefix not in {"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}:
        return False
    body = value[4:]
    return all(c.isalnum() or c == "_" for c in body)


def _validate_slack_bot(value: str) -> bool:
    """Slack tokens have shape xox[abprs]-NNNN-NNNN-..."""
    parts = value.split("-")
    return len(parts) >= 4 and parts[0].startswith("xox")


SECRET_PATTERNS = [
    # ── Cloud: AWS ──────────────────────────────────────────────────────
    SecretPattern("AWS Access Key ID",
        r"(?:^|['\"\s=:])(?P<secret>(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA)[0-9A-Z]{16})(?:['\"\s]|$)",
        Severity.CRITICAL, min_len=20,
        validator=_validate_aws_access_key, confidence=Confidence.CONFIRMED),
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
        Severity.CRITICAL, min_len=40,
        validator=_validate_github_token, confidence=Confidence.CONFIRMED),
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
        Severity.CRITICAL, min_len=60,
        validator=_validate_slack_bot, confidence=Confidence.CONFIRMED),
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
        Severity.CRITICAL, min_len=30,
        validator=_validate_stripe_key, confidence=Confidence.CONFIRMED),
    SecretPattern("Stripe Publishable Key",
        r"(?P<secret>pk_live_[0-9a-zA-Z]{24,})",
        Severity.MEDIUM, min_len=30,
        validator=_validate_stripe_key, confidence=Confidence.CONFIRMED),
    SecretPattern("Stripe Restricted Key",
        r"(?P<secret>rk_live_[0-9a-zA-Z]{24,})",
        Severity.CRITICAL, min_len=30,
        validator=_validate_stripe_key, confidence=Confidence.CONFIRMED),
    SecretPattern("Stripe Webhook Signing Secret",
        r"(?P<secret>whsec_[A-Za-z0-9]{32,})",
        Severity.HIGH, min_len=38, confidence=Confidence.HIGH),
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
        Severity.HIGH, min_len=50,
        validator=_validate_jwt, confidence=Confidence.CONFIRMED),

    # ── AI / LLM providers ──────────────────────────────────────────────
    SecretPattern("OpenAI API Key",
        r"(?P<secret>sk-(?:proj-)?[A-Za-z0-9_-]{20,})",
        Severity.CRITICAL, min_len=24, confidence=Confidence.HIGH),
    SecretPattern("Anthropic API Key",
        r"(?P<secret>sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})",
        Severity.CRITICAL, min_len=90, confidence=Confidence.CONFIRMED),
    SecretPattern("Cohere API Key",
        r"(?:cohere.*(?:api.?key|token))\s*[=:]\s*['\"](?P<secret>[A-Za-z0-9]{40})['\"]",
        Severity.HIGH, min_len=40),
    SecretPattern("Replicate API Token",
        r"(?P<secret>r8_[A-Za-z0-9]{37,})",
        Severity.HIGH, min_len=40, confidence=Confidence.HIGH),

    # ── Cloud (additional) ──────────────────────────────────────────────
    SecretPattern("Google Service Account Private Key",
        r"(?P<secret>\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----)",
        Severity.CRITICAL, min_len=50, confidence=Confidence.CONFIRMED),
    SecretPattern("Cloudflare API Token",
        r"(?:cf|cloudflare).*(?:api.?token|api.?key)\s*[=:]\s*['\"](?P<secret>[A-Za-z0-9_-]{40})['\"]",
        Severity.HIGH, min_len=40),

    # ── DevOps / CI ─────────────────────────────────────────────────────
    SecretPattern("Vault Token",
        r"(?P<secret>hvs\.[A-Za-z0-9_-]{90,100})",
        Severity.CRITICAL, min_len=94, confidence=Confidence.HIGH),
    SecretPattern("Datadog API Key",
        r"(?:datadog.*(?:api.?key))\s*[=:]\s*['\"](?P<secret>[a-f0-9]{32})['\"]",
        Severity.HIGH, min_len=32),
    SecretPattern("New Relic License Key",
        r"(?:new.?relic.*(?:license|key))\s*[=:]\s*['\"](?P<secret>[A-Fa-f0-9]{40}NRAL)['\"]",
        Severity.HIGH, min_len=44),
    SecretPattern("Linear API Key",
        r"(?P<secret>lin_api_[A-Za-z0-9]{40})",
        Severity.HIGH, min_len=48, confidence=Confidence.HIGH),
    SecretPattern("Notion Integration Token",
        r"(?P<secret>(?:secret_|ntn_)[A-Za-z0-9]{43,50})",
        Severity.HIGH, min_len=50, confidence=Confidence.HIGH),

    # ── Square / Shopify / commerce ─────────────────────────────────────
    SecretPattern("Square Access Token",
        r"(?P<secret>EAAA[A-Za-z0-9_-]{60})",
        Severity.CRITICAL, min_len=64, confidence=Confidence.HIGH),
    SecretPattern("Shopify Access Token",
        r"(?P<secret>shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})",
        Severity.CRITICAL, min_len=38, confidence=Confidence.CONFIRMED),

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

    def __init__(self, target_path: str, scan_git_history: bool = True,
                 max_history_commits: int = 2000):
        super().__init__(target_path)
        # Git history scanning is opt-out via constructor; disable in tests
        # or when scanning a non-repo target. Caps the commit walk so a huge
        # monorepo doesn't stall the scan.
        self.scan_git_history = scan_git_history
        self.max_history_commits = max_history_commits

    def scan(self) -> ScanResult:
        start = time.time()
        result = ScanResult(scanner_name=self.name)

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [
                d for d in dirs
                if not should_skip_dir(d) and d not in SKIP_DIRS
            ]

            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()

                # Check extension and skip noisy files (minified bundles etc.)
                if should_skip_file(fname):
                    continue
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

        # Pass 2: scan git history for secrets in old commits.
        if self.scan_git_history:
            self._scan_git_history(result)

        result.scan_time_seconds = time.time() - start
        return result

    def _scan_git_history(self, result: ScanResult):
        """Walk the last N commits looking for secret patterns in added lines.

        Findings already present in the working tree are deduped (no point
        flagging the same leak twice). History-only findings get a clear
        title prefix and include the commit/author/date so the user can
        rotate the credential AND know who needs to be notified.
        """
        from core.git_history import iter_added_lines, is_git_repo, get_origin_url, short_commit_url
        if not is_git_repo(self.target_path):
            return

        origin = get_origin_url(self.target_path)
        # Build set of (file, line_text_first_80_chars) we already reported
        # in the working tree to avoid duplicates.
        already_reported: set[tuple[str, str]] = {
            (f.file_path, f.code_snippet[:80]) for f in result.findings
        }

        history_findings: list[Finding] = []
        seen_secrets: set[tuple[str, str, str]] = set()  # (pattern_name, file, masked_value)

        for hl in iter_added_lines(self.target_path, max_commits=self.max_history_commits):
            if (hl.file_path, hl.line_text[:80]) in already_reported:
                continue

            for sp in SECRET_PATTERNS:
                m = sp.regex.search(hl.line_text)
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
                if sp.validator is not None and not sp.validator(secret_value):
                    continue

                masked = secret_value[:4] + "*" * min(len(secret_value) - 4, 20)
                key = (sp.name, hl.file_path, masked)
                if key in seen_secrets:
                    continue
                seen_secrets.add(key)

                commit_url = short_commit_url(hl.commit, origin)
                url_line = f"\n  Commit URL: {commit_url}" if commit_url else ""
                history_findings.append(Finding(
                    title=f"[GIT HISTORY] {sp.name}",
                    severity=sp.severity,
                    category=Category.SECRETS,
                    file_path=f"{hl.file_path} @ {hl.commit}",
                    line_number=None,
                    code_snippet=f"[REDACTED] {masked}",
                    description=(
                        f"Secret found in git history (no longer in working tree).\n"
                        f"  Commit:  {hl.commit}\n"
                        f"  Author:  {hl.author}\n"
                        f"  Date:    {hl.date}{url_line}\n"
                        f"Even though the file no longer contains this value, "
                        f"every clone of the repo still has it."
                    ),
                    recommendation=(
                        "1. ROTATE the credential NOW (assume it is public).\n"
                        "2. Optionally rewrite history with git-filter-repo or BFG to remove the blob.\n"
                        "3. Force-push and notify all clones (CI runners, dev machines, mirrors)."
                    ),
                    cwe_id="CWE-798",
                    attack_simulation=(
                        f"Anyone who cloned this repo at any point has the secret. "
                        f"Public repos: GitHub indexes commits — bots scrape new commits within minutes."
                    ),
                    confidence=sp.confidence,
                ))
                break  # one finding per matched line

        result.findings.extend(history_findings)

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
                            confidence=Confidence.HIGH,
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

                # Structural validation: discard obvious false positives
                # (e.g. JWT-shaped strings whose header isn't valid base64
                # JSON, AWS-shaped strings that fail prefix/length check).
                if sp.validator is not None and not sp.validator(secret_value):
                    continue

                # Live verification: if SECURITY_GUARD_VERIFY_SECRETS=1 is set
                # and a verifier exists for this secret type, hit the vendor's
                # whoami endpoint. VERIFIED → upgrade to CONFIRMED + CRITICAL.
                verify_result = verify_secret_live(sp.name, secret_value)
                title = sp.name
                conf = sp.confidence
                sev = sp.severity
                extra_desc = ""
                if verify_result is not None:
                    if verify_result.status == "VERIFIED":
                        title = f"{sp.name} [VERIFIED ACTIVE]"
                        conf = Confidence.CONFIRMED
                        sev = Severity.CRITICAL
                        extra_desc = f"\n\n>>> LIVE CHECK: ACTIVE — {verify_result.detail}"
                    elif verify_result.status == "UNVERIFIED":
                        title = f"{sp.name} [revoked/invalid]"
                        # Keep finding but downgrade — historic exposure still
                        # matters (the secret WAS valid before rotation).
                        sev = Severity.MEDIUM
                        extra_desc = f"\n\n>>> LIVE CHECK: rejected by vendor — {verify_result.detail}"

                masked = secret_value[:4] + "*" * min(len(secret_value) - 4, 20)
                findings.append(Finding(
                    title=title,
                    severity=sev,
                    category=Category.SECRETS,
                    file_path=rel_path,
                    line_number=i,
                    code_snippet=f"[REDACTED] {masked}",
                    description=f"Detected {sp.name} pattern. If real, this credential is exposed.{extra_desc}",
                    recommendation=(
                        "- Remove from source code and git history (git-filter-repo or BFG)\n"
                        "- Rotate the credential immediately in the service's dashboard\n"
                        "- Store secrets in environment variables or a secrets manager"
                    ),
                    cwe_id="CWE-798",
                    attack_simulation=f"An exposed {sp.name} grants immediate access to the associated service. Search engines and bot scanners index public repos continuously.",
                    confidence=conf,
                ))
                reported_lines.add(i)
                break  # One finding per line

            # ── High-entropy string detection ───────────────────────────
            if i in reported_lines:
                continue

            # Pre-filter: only consider lines that mention a credential
            # keyword. Eliminates ~95% of FPs (UUIDs, hashes, base64 images).
            if not has_credential_context(line):
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
                        confidence=Confidence.LOW,
                    ))
                    reported_lines.add(i)

        return findings
