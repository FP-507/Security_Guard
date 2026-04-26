"""Base scanner class for all Security Guard scanners."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Iterable
import os


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> int:
        return {
            "CRITICAL": 10,
            "HIGH": 8,
            "MEDIUM": 5,
            "LOW": 3,
            "INFO": 1,
        }[self.value]


class Confidence(Enum):
    """How confident the scanner is that a finding is a true positive.

    - CONFIRMED: validated (e.g. AWS key checksum passes, AST taint flow proven)
    - HIGH: strong signal, low historical false-positive rate
    - MEDIUM: pattern matches but context could not be fully verified
    - LOW: heuristic / entropy-based; review manually
    """

    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def weight(self) -> float:
        return {
            "CONFIRMED": 1.0,
            "HIGH": 0.85,
            "MEDIUM": 0.6,
            "LOW": 0.35,
        }[self.value]


class Category(Enum):
    INJECTION = "Injection (A03:2021)"
    BROKEN_AUTH = "Broken Authentication (A07:2021)"
    SENSITIVE_DATA = "Sensitive Data Exposure (A02:2021)"
    SECURITY_MISCONFIG = "Security Misconfiguration (A05:2021)"
    XSS = "Cross-Site Scripting (A03:2021)"
    INSECURE_DESERIALIZATION = "Insecure Deserialization (A08:2021)"
    VULNERABLE_COMPONENTS = "Vulnerable Components (A06:2021)"
    BROKEN_ACCESS = "Broken Access Control (A01:2021)"
    LOGGING = "Insufficient Logging (A09:2021)"
    SSRF = "Server-Side Request Forgery (A10:2021)"
    SECRETS = "Hardcoded Secrets"
    FILE_INCLUSION = "File Inclusion / Path Traversal"
    CRYPTO = "Weak Cryptography (A02:2021)"


# Directories that almost always produce noise (third-party code, build output,
# version control, virtualenvs, IDE caches). Scanners should skip these to reduce
# false positives and dramatically speed up scans on large repos.
SKIP_DIRS: frozenset[str] = frozenset({
    # VCS
    ".git", ".hg", ".svn",
    # Python
    "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "site-packages", "egg-info",
    # JS / TS
    "node_modules", "bower_components", ".next", ".nuxt", ".cache",
    "dist", "build", "out", ".parcel-cache", ".turbo",
    # Ruby / PHP / Java / Go
    "vendor", "target", ".gradle", ".idea", ".m2",
    # Misc
    "coverage", "htmlcov", ".coverage", ".nyc_output",
    "reports",  # security-guard's own reports dir
    ".DS_Store",
})

# File patterns where matches are almost always noise (minified, source maps,
# bundled vendor files, lockfiles). Scanners should skip these.
SKIP_FILE_SUFFIXES: tuple[str, ...] = (
    ".min.js", ".min.css", ".bundle.js", ".chunk.js",
    ".map", ".lock",
    ".pyc", ".pyo", ".so", ".dll", ".dylib", ".class", ".jar", ".war",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".7z",
    ".woff", ".woff2", ".ttf", ".eot",
)


def should_skip_dir(dirname: str) -> bool:
    """True if a directory name should be excluded from scanning."""
    return dirname in SKIP_DIRS or dirname.endswith(".egg-info")


def should_skip_file(filename: str) -> bool:
    """True if a filename should be excluded (minified, binary, lockfile)."""
    lower = filename.lower()
    return any(lower.endswith(suf) for suf in SKIP_FILE_SUFFIXES)


# Files containing this marker in their first ~2KB are skipped by every
# scanner. We use it inside Security Guard's own pattern-definition files so
# that scanning the tool's own source does not flag every embedded regex /
# example payload as a real vulnerability. Apply sparingly — it disables ALL
# detection for the file.
IGNORE_FILE_MARKER = "security-guard: ignore-file"


def has_ignore_marker(path: str) -> bool:
    """True if `path` declares it should be skipped by Security Guard.

    Reads only the first 2KB so the cost is bounded even on very large files.
    Returns False on any read error so unreadable files still go through the
    normal scanning path (which already handles them defensively).
    """
    try:
        with open(path, "rb") as f:
            head = f.read(2048)
        return IGNORE_FILE_MARKER.encode("ascii") in head
    except OSError:
        return False


def should_skip_source(fpath: str) -> bool:
    """Combined check: filename-based skip OR file declares ignore marker."""
    return should_skip_file(os.path.basename(fpath)) or has_ignore_marker(fpath)


def iter_source_files(
    root: str,
    extensions: Optional[Iterable[str]] = None,
) -> Iterable[str]:
    """Walk `root` yielding absolute file paths, skipping vendored/build dirs.

    Pass `extensions` (e.g. {".py", ".js"}) to filter by suffix.
    """
    ext_set = {e.lower() for e in extensions} if extensions else None
    for dirpath, dirnames, filenames in os.walk(root):
        # Mutate dirnames in place so os.walk does not descend into skipped dirs.
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        for fn in filenames:
            if should_skip_file(fn):
                continue
            if ext_set is not None:
                _, ext = os.path.splitext(fn)
                if ext.lower() not in ext_set:
                    continue
            full = os.path.join(dirpath, fn)
            if has_ignore_marker(full):
                continue
            yield full


@dataclass
class Finding:
    title: str
    severity: Severity
    category: Category
    file_path: str
    line_number: Optional[int]
    code_snippet: str
    description: str
    recommendation: str
    cwe_id: Optional[str] = None
    attack_simulation: Optional[str] = None
    root_cause: Optional[str] = None       # WHY the vulnerability exists (underlying flaw)
    consequences: Optional[str] = None     # Business/security impact if exploited
    confidence: Confidence = Confidence.MEDIUM  # Likelihood this is a true positive

    @property
    def score(self) -> int:
        return self.severity.score

    @property
    def weighted_score(self) -> float:
        """Severity score weighted by confidence — useful for ranking."""
        return self.severity.score * self.confidence.weight


@dataclass
class ScanResult:
    scanner_name: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    scan_time_seconds: float = 0.0

    @property
    def total_score(self) -> int:
        return sum(f.score for f in self.findings)

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.score).severity


class BaseScanner:
    name: str = "BaseScanner"

    def __init__(self, target_path: str):
        self.target_path = target_path

    def scan(self) -> ScanResult:
        raise NotImplementedError

    # ----- Shared helpers (used by subclasses) -----

    def iter_files(self, extensions: Optional[Iterable[str]] = None) -> Iterable[str]:
        """Yield source files under the target path with noise dirs filtered out."""
        return iter_source_files(self.target_path, extensions=extensions)

    @staticmethod
    def is_test_or_example_path(path: str) -> bool:
        """Heuristic: True if path looks like test/example/fixture code.

        Scanners can downgrade severity or skip findings inside tests to
        avoid flagging intentionally-bad sample code.
        """
        norm = path.replace("\\", "/").lower()
        markers = ("/test/", "/tests/", "/__tests__/", "/spec/", "/specs/",
                   "/example/", "/examples/", "/fixtures/", "/mocks/",
                   "/sample/", "/samples/", "/demo/", "/demos/")
        return any(m in norm for m in markers)
