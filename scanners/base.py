"""Base scanner class for all Security Guard scanners."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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

    @property
    def score(self) -> int:
        return self.severity.score


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
