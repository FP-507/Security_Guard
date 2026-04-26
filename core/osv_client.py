"""OSV.dev API client — queries the Open Source Vulnerability database.

OSV aggregates GHSA, PyPA, RustSec, Go vulndb, npm, Maven, NuGet, RubyGems
and other ecosystem advisories under a single schema. Using it replaces our
~100-entry hardcoded CVE list with the canonical, always-fresh dataset.

Docs: https://google.github.io/osv.dev/api/
Endpoint: POST https://api.osv.dev/v1/querybatch
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib import request as _urlreq, error as _urlerr

OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"
OSV_VULN_ENDPOINT = "https://api.osv.dev/v1/vulns/{}"

# OSV ecosystem identifiers — see https://ossf.github.io/osv-schema/#affectedpackage-field
ECOSYSTEM = {
    "python": "PyPI",
    "pypi": "PyPI",
    "javascript": "npm",
    "npm": "npm",
    "ruby": "RubyGems",
    "rubygems": "RubyGems",
    "go": "Go",
    "rust": "crates.io",
    "java": "Maven",
    "maven": "Maven",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "php": "Packagist",
}


@dataclass
class OsvQuery:
    """One row in a batched OSV query."""
    ecosystem: str
    package: str
    version: str
    # Caller-supplied tag (file path + line number) so results map back.
    ref: tuple = ()


@dataclass
class OsvVuln:
    """A single OSV advisory result, normalized for our Finding model."""
    id: str                       # e.g. GHSA-xxxx, CVE-2024-xxxx, PYSEC-xxxx
    summary: str
    severity: str                 # CRITICAL/HIGH/MEDIUM/LOW (best-effort)
    fix_version: Optional[str]    # first fixed version if known
    aliases: list[str]            # related CVE/GHSA IDs
    references: list[str]         # URLs (advisories, commits, blogs)


def _http_post_json(url: str, body: dict, timeout: float = 8.0) -> Optional[dict]:
    """Tiny JSON POST helper using only stdlib (no requests dep needed)."""
    try:
        data = json.dumps(body).encode("utf-8")
        req = _urlreq.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "security-guard/1.0"},
            method="POST",
        )
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (_urlerr.URLError, _urlerr.HTTPError, TimeoutError, OSError, ValueError):
        return None


def _http_get_json(url: str, timeout: float = 8.0) -> Optional[dict]:
    try:
        req = _urlreq.Request(url, headers={"User-Agent": "security-guard/1.0"})
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (_urlerr.URLError, _urlerr.HTTPError, TimeoutError, OSError, ValueError):
        return None


def _severity_from_osv(adv: dict) -> str:
    """Best-effort severity extraction from an OSV advisory dict.

    OSV stores severity in `severity[]` (CVSS) and `database_specific.severity`.
    GHSA entries carry an explicit severity string; CVSS scores get bucketed.
    """
    db = adv.get("database_specific") or {}
    raw = db.get("severity")
    if isinstance(raw, str) and raw.upper() in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"):
        return "MEDIUM" if raw.upper() == "MODERATE" else raw.upper()

    for sev in adv.get("severity", []) or []:
        score = sev.get("score", "")
        # Parse "CVSS:3.1/AV:N/..." → look for explicit base score in metadata
        # If only the vector is present, leave bucketing to 0 — many OSV
        # entries lack a numeric base score so we fall through.
        if isinstance(score, (int, float)):
            return _bucket_cvss(float(score))
        if isinstance(score, str) and "/" not in score:
            try:
                return _bucket_cvss(float(score))
            except ValueError:
                pass
    return "MEDIUM"


def _bucket_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _first_fixed_version(adv: dict, ecosystem: str, package: str) -> Optional[str]:
    """Walk affected[].ranges[].events to find the lowest 'fixed' version."""
    fixed_candidates: list[str] = []
    for aff in adv.get("affected", []) or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if pkg.get("name", "").lower() != package.lower():
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixed_candidates.append(ev["fixed"])
    return fixed_candidates[0] if fixed_candidates else None


class OsvClient:
    """Batched OSV query client with simple in-process caching.

    Use `query_packages()` to hit the API once for many packages. The client
    silently degrades to returning an empty list on network/parse errors so
    offline scans still work — the caller should fall back to the hardcoded
    CVE list in that case.
    """

    def __init__(self, batch_size: int = 100, enabled: bool = True):
        self.batch_size = batch_size
        self.enabled = enabled
        self._cache: dict[tuple[str, str, str], list[OsvVuln]] = {}
        self._vuln_cache: dict[str, dict] = {}
        # Soft circuit breaker: after N consecutive failures, stop trying.
        self._failures = 0
        self._max_failures = 3

    @property
    def healthy(self) -> bool:
        return self.enabled and self._failures < self._max_failures

    def query_packages(self, queries: list[OsvQuery]) -> dict[tuple, list[OsvVuln]]:
        """Returns {ref: [OsvVuln, ...]} for each query that had hits."""
        if not self.healthy or not queries:
            return {}

        results: dict[tuple, list[OsvVuln]] = {}
        # Split into batches to respect OSV's request size limits.
        for start in range(0, len(queries), self.batch_size):
            batch = queries[start:start + self.batch_size]
            batch_results = self._query_batch(batch)
            results.update(batch_results)
        return results

    def _query_batch(self, batch: list[OsvQuery]) -> dict[tuple, list[OsvVuln]]:
        body = {
            "queries": [
                {
                    "package": {"ecosystem": q.ecosystem, "name": q.package},
                    "version": q.version,
                }
                for q in batch
            ]
        }
        resp = _http_post_json(OSV_BATCH_ENDPOINT, body, timeout=10.0)
        if resp is None:
            self._failures += 1
            return {}
        self._failures = 0  # reset on success

        out: dict[tuple, list[OsvVuln]] = {}
        for q, entry in zip(batch, resp.get("results", [])):
            vuln_refs = entry.get("vulns") or []
            if not vuln_refs:
                continue
            cached = self._cache.get((q.ecosystem, q.package, q.version))
            if cached is not None:
                out[q.ref] = cached
                continue

            vulns: list[OsvVuln] = []
            for vref in vuln_refs:
                vuln_id = vref.get("id")
                if not vuln_id:
                    continue
                full = self._fetch_vuln(vuln_id)
                if full is None:
                    continue
                vulns.append(OsvVuln(
                    id=vuln_id,
                    summary=full.get("summary") or full.get("details", "")[:200],
                    severity=_severity_from_osv(full),
                    fix_version=_first_fixed_version(full, q.ecosystem, q.package),
                    aliases=full.get("aliases", []) or [],
                    references=[r.get("url", "") for r in (full.get("references") or [])],
                ))
            self._cache[(q.ecosystem, q.package, q.version)] = vulns
            out[q.ref] = vulns
        return out

    def _fetch_vuln(self, vuln_id: str) -> Optional[dict]:
        """Fetch the full advisory by ID. The querybatch endpoint only returns
        IDs, so we hydrate each one to get summary/severity/fix-version."""
        if vuln_id in self._vuln_cache:
            return self._vuln_cache[vuln_id]
        full = _http_get_json(OSV_VULN_ENDPOINT.format(vuln_id), timeout=8.0)
        if full is None:
            self._failures += 1
            return None
        self._vuln_cache[vuln_id] = full
        return full
