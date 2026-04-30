"""Single source of truth for the scanner registry.

Both the Flask web server (``app.py``) and the CLI (``security_guard.py``)
import from here. If a scanner is added or renamed, this is the **only** place
that needs to change — the dashboard's ``/api/scanners`` endpoint, the CLI's
``--scanners`` argument and the documentation strings all read from this list.

Each scanner entry declares which **kind** of target it accepts:

    "code" → local filesystem path (or a cloned GitHub repo's temp dir)
    "web"  → an ``http(s)://`` URL of a live website

The web dashboard mode hides "code" scanners when scanning a website URL and
vice-versa; the CLI silently ignores "web" entries when scanning a path.
"""

from dataclasses import dataclass
from typing import Literal, Type

from .base import BaseScanner
from .static_analyzer import StaticAnalyzer
from .secret_detector import SecretDetector
from .dependency_scanner import DependencyScanner
from .config_auditor import ConfigAuditor
from .attack_simulator import AttackSimulator
from .insecure_defaults import InsecureDefaultsScanner
from .web_auditor import WebAuditor


ScannerKind = Literal["code", "web"]


@dataclass(frozen=True)
class ScannerEntry:
    """Metadata for a single scanner — drives both UI and CLI."""
    key: str                    # short id used by the API and --scanners CLI flag
    name: str                   # human-readable name shown in the UI
    cls: Type[BaseScanner]      # class instantiated as ``cls(target_path_or_url)``
    description: str            # one-line description shown next to the toggle
    kind: ScannerKind = "code"  # "code" → filesystem; "web" → live URL


# ── The canonical scanner list ────────────────────────────────────────────────
# Order here defines the order shown in the dashboard and the order scanners
# run when "all" is selected from the CLI.
SCANNERS: list[ScannerEntry] = [
    ScannerEntry(
        "static",   "Static Code Analyzer",            StaticAnalyzer,
        "Analyzes code for injection, XSS, crypto, and other vulnerability patterns",
    ),
    ScannerEntry(
        "secrets",  "Secret Detector",                 SecretDetector,
        "Finds API keys, tokens, passwords, and high-entropy strings",
    ),
    ScannerEntry(
        "deps",     "Dependency Scanner",              DependencyScanner,
        "Checks packages against known CVE databases",
    ),
    ScannerEntry(
        "config",   "Config Auditor",                  ConfigAuditor,
        "Reviews Docker, CI/CD, .gitignore, SSL, and server configs",
    ),
    ScannerEntry(
        "defaults", "Insecure Defaults (Trail of Bits)", InsecureDefaultsScanner,
        "Detects fail-open patterns: fallback secrets, auth disabled by default, weak crypto in context",
    ),
    ScannerEntry(
        "attacks",  "Attack Simulator",                AttackSimulator,
        "Simulates SQL injection, XSS, CSRF, IDOR, SSRF, supply chain, and more",
    ),
    ScannerEntry(
        "web",      "Web Auditor",                     WebAuditor,
        "Black-box web scanner: security headers, cookies, CORS, XSS, open redirect, secret leakage, and more",
        kind="web",
    ),
]


# ── Convenience views (kept in sync automatically) ────────────────────────────

def code_scanners() -> list[ScannerEntry]:
    """Scanners that accept a filesystem path."""
    return [s for s in SCANNERS if s.kind == "code"]


def web_scanners() -> list[ScannerEntry]:
    """Scanners that accept a live URL."""
    return [s for s in SCANNERS if s.kind == "web"]


def by_key() -> dict[str, ScannerEntry]:
    """Lookup table ``{"static": ScannerEntry(...), ...}``."""
    return {s.key: s for s in SCANNERS}


def keys() -> list[str]:
    """Just the short ids — useful for argparse ``choices=``."""
    return [s.key for s in SCANNERS]
